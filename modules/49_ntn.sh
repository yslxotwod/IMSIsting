#!/usr/bin/env bash
# ntn — 5G non-terrestrial networks: propagation delays, Doppler and K_offset.
#
# A satellite cell is a normal NR cell with two extra problems: a round-trip
# delay far larger than any terrestrial timing assumes, and a Doppler shift that
# scales with the closing velocity. 3GPP answers both in SIB19 (TA, K_offset,
# ephemeris, cell reference location, mobility). This module computes the delays
# and Doppler for the geometry you supply, and converts the SIB19 K_offset.
#
# K_offset is counted in 15 kHz reference slots, i.e. 1 ms each: TS 38.331
# NTN-Config field description ("The unit of the field K_offset is number of
# slots for a given subcarrier spacing of 15 kHz"), and TS 38.213 clause 9 adds
# 2^(mu-mu_Koffset)*K_offset slots in the carrier's numerology with
# mu_Koffset = 0 in FR1 and in FR2-NTN. So the carrier SCS changes the slot
# count the UE schedules with, not the delay in milliseconds. SIB19 is
# decoded and built through the generated NR table (--sib19, --sib19-build).
#
# The other half is the orbit. SIB19 carries a state vector, and something has
# to produce it: an element set is propagated with SGP4 (near-earth, Vallado
# AIAA 2006-6753) to give where the satellite is over the next pass, which is
# what turns the timing verbs above from a single measurement into a schedule.
# Direct-to-device (a handset talking to a satellite with no dish) is the same
# geometry read the other way round, which is why it lives here rather than in a
# module of its own: one implementation per number.
#
# Attack owned: the feeder link — the gateway's geometry, the uplink budget that
# decides whether a bent-pipe transponder saturates, and the carrier ratio a
# capture needs, all from an element set and a ground coordinate. The service
# link stays analysis: cell reconnaissance and timing analysis for NTN access
# (extends 02_cell_recon and 12_nr_air to a satellite cell).
#
# Resolve IMSISTING_ROOT from this script's own path (MODULE_CONVENTIONS §2).
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null

MOD_TMP="$TMP_DIR/ntn"
NTN_DIR="$LOOT_DIR/ntn"
mkdir -p "$MOD_TMP" "$NTN_DIR" 2>/dev/null

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F banner >/dev/null 2>&1 || banner() { :; }

# ── orbital mechanics: the ephemeris half of NTN ────────────────────────
# SIB19 tells a UE where the satellite is. Something has to work out where the
# satellite is, and for a LEO that means propagating an element set rather than
# reading a fixed latitude. SGP4 (Vallado, AIAA 2006-6753) is what the two-line
# element sets the network broadcasts are defined against, so it is what this
# module implements -- near-earth only, with a deep-space element set refused by
# name instead of being propagated with the wrong model.
#
# Speed of light in km/s. Every delay here is a range divided by it.
NTN_C_KM_S=299792.458
# One LTE timing-advance step is 16 Ts with Ts = 1/(15000*2048) s = 0.5208 us.
# NR keeps the same command granularity (16*64*Tc with Tc = 1/(480e3*4096)),
# which lands on the same 0.5208 us -- so one constant is honest for both.
NTN_TA_STEP_US=0.5208
# WGS-84 mean Earth radius, for footprints and horizon geometry.
NTN_R_EARTH_KM=6371.0088


# ── TLE parsing ─────────────────────────────────────────────────────────
# A TLE is fixed-column, and the columns are the specification: the eccentricity
# has an implied leading decimal point, the epoch is a two-digit year plus a
# fractional day of year, and the last character of each line is a mod-10
# checksum where '-' counts as 1. A parser that splits on whitespace reads the
# wrong field the first time a number loses its leading space.
ntn_tle_checksum() {
    printf '%s' "${1:-}" | awk '{
        s=0
        for (i=1; i<length($0); i++) {
            c=substr($0,i,1)
            if (c ~ /[0-9]/) s += c+0
            else if (c == "-") s += 1
        }
        print s % 10
    }'
}

ntn_tle_get() {
    local file="${1:-}" which="${2:-1}"
    [[ -r "$file" ]] || { printf 'ERROR\tcannot read TLE file %s\n' "$file" >&2; return 2; }
    # A three-line element set starts with the object name; a two-line one does
    # not. Pick the first line that actually starts with "1 ".
    awk -v want="$which" '
        /^1 / { n++; if (n==1) l1=$0 }
        /^2 / { if (l1 != "" && l2 == "") l2=$0 }
        END {
            if (want==1) print l1; else print l2
        }' "$file"
}

ntn_tle_parse() {
    local file="${1:-}"
    local l1 l2
    l1=$(ntn_tle_get "$file" 1) || return $?
    l2=$(ntn_tle_get "$file" 2) || return $?
    [[ -n "$l1" && -n "$l2" ]] || {
        printf 'GUARD\tno-two-line-element-set\trefusing: the file has no line starting "1 " followed by one starting "2 ". An empty parse would read as a satellite with no orbit.\n'
        return 1; }

    printf 'field\tvalue\tnote\n'
    printf 'line1\t%s\t\n' "$(ntn_sanitize "$l1")"
    printf 'line2\t%s\t\n' "$(ntn_sanitize "$l2")"
    printf 'satnum\t%s\t\n' "$(ntn_sanitize "$(printf '%s' "$l1" | cut -c3-7 | tr -d ' ')")"

    local yy ddd year iso
    yy=$(printf '%s' "$l1" | cut -c19-20 | tr -d ' ')
    ddd=$(printf '%s' "$l1" | cut -c21-32 | tr -d ' ')
    if [[ "$yy" =~ ^[0-9]+$ ]]; then
        # The pivot is 57: a two-digit year below it is 20xx, at or above it 19xx.
        if (( 10#$yy < 57 )); then year=$((2000 + 10#$yy)); else year=$((1900 + 10#$yy)); fi
        printf 'epoch-year\t%s\tTLE two-digit year, pivot 57\n' "$year"
        printf 'epoch-day\t%s\tfractional day of year\n' "$ddd"
        iso=$(ntn_epoch_iso "$year" "$ddd")
        printf 'epoch-utc\t%s\t\n' "$iso"
    else
        printf 'epoch-year\tunobserved\tthe epoch column is not numeric\n'
        iso=""
    fi

    printf 'inclination-deg\t%s\tcolumns 9-16\n' "$(printf '%s' "$l2" | cut -c9-16 | tr -d ' ')"
    printf 'raan-deg\t%s\tcolumns 18-25\n' "$(printf '%s' "$l2" | cut -c18-25 | tr -d ' ')"
    local eccraw; eccraw=$(printf '%s' "$l2" | cut -c27-33 | tr -d ' ')
    printf 'eccentricity\t0.%s\timplied leading decimal point\n' "$eccraw"
    printf 'argp-deg\t%s\tcolumns 35-42\n' "$(printf '%s' "$l2" | cut -c35-42 | tr -d ' ')"
    printf 'mean-anomaly-deg\t%s\tcolumns 44-51\n' "$(printf '%s' "$l2" | cut -c44-51 | tr -d ' ')"
    local mm; mm=$(printf '%s' "$l2" | cut -c53-63 | tr -d ' ')
    printf 'mean-motion-revday\t%s\tcolumns 53-63\n' "$mm"
    if [[ "$mm" =~ ^[0-9.]+$ ]]; then
        awk -v n="$mm" 'BEGIN{
            period = 1440.0 / n
            printf "period-min\t%.4f\tderived: 1440 / mean motion\n", period
            # semi-major axis from the third law of Kepler, mu = 398600.8 km^3/s^2
            mu = 398600.8
            secs = period * 60.0
            a = (mu * (secs/(2*3.141592653589793))^2) ^ (1.0/3.0)
            printf "semi-major-axis-km\t%.3f\tderived from period and mu\n", a
            printf "apogee-km\t%.1f\tderived\n", a*(1+ecc) - 6378.135
            printf "perigee-km\t%.1f\tderived; below 220 km a decayed orbit is likely\n", a*(1-ecc) - 6378.135
        }' ecc="${eccraw:-0}" 2>/dev/null || true
    fi

    local c1 c2
    c1=$(printf '%s' "$l1" | cut -c69-69)
    c2=$(printf '%s' "$l2" | cut -c69-69)
    if [[ "$c1" =~ ^[0-9]$ ]]; then
        printf 'checksum-line1\t%s\tcomputed %s\n' "$c1" "$(ntn_tle_checksum "$l1")"
    else
        printf 'checksum-line1\tunobserved\tno checksum column present\n'
    fi
    if [[ "$c2" =~ ^[0-9]$ ]]; then
        printf 'checksum-line2\t%s\tcomputed %s\n' "$c2" "$(ntn_tle_checksum "$l2")"
    else
        printf 'checksum-line2\tunobserved\tno checksum column present\n'
    fi
    printf 'verdict\tparsed\tmeasured\n'
}

# Year + fractional day of year -> ISO 8601 UTC. Done in awk because the day
# fraction has to survive; date(1) cannot add a fractional day.
ntn_epoch_iso() {
    awk -v y="$1" -v d="$2" 'BEGIN{
        if (d == "") { print "unobserved"; exit }
        doy = d + 0
        secs = (doy - 1) * 86400
        # days from 1970-01-01 to Jan 1 of year y
        days = 0
        for (yy = 1970; yy < y; yy++) days += ((yy%4==0 && yy%100!=0) || yy%400==0) ? 366 : 365
        t = (days*86400) + secs
        printf "%s\n", strftime("%Y-%m-%dT%H:%M:%SZ", t, 1)
    }'
}

# ── SGP4 ────────────────────────────────────────────────────────────────
# The near-earth branch of SGP4, WGS-72 constants, exactly as published in
# Vallado's sgp4unit. The deep-space (SDP4) branch is deliberately absent: the
# D2D constellations are all well inside the 225-minute period boundary, and an
# implementation that silently fell back to a truncated model for a
# geostationary satellite would be confidently wrong about a satellite that
# moves 0 degrees per second. A deep-space element set is refused by name.
ntn_sgp4() {
    local l1="${1:-}" l2="${2:-}" tsince="${3:-0}"
    awk -v L1="$l1" -v L2="$l2" -v TSINCE="$tsince" '
    function absv(x) { return x < 0 ? -x : x }
    BEGIN {
        pi = atan2(0, -1); twopi = 2*pi; x2o3 = 2.0/3.0
        mu = 398600.8; radiusearthkm = 6378.135; j2 = 0.001082616
        j3 = -0.00000253881; j4 = -0.00000165597; j3oj2 = j3/j2
        xpdotp = 1440.0/twopi
        xke = 60.0/sqrt(radiusearthkm*radiusearthkm*radiusearthkm/mu)

        # fixed columns, both lines
        yy   = substr(L1,19,2) + 0
        doy  = substr(L1,21,12) + 0
        bstr = substr(L1,54,8)
        bs   = substr(bstr,1,1) == "-" ? -1 : 1
        bmant= substr(bstr,2,5) + 0
        bexp = substr(bstr,7,1) == "-" ? -1 : 1
        bdig = substr(bstr,8,1) + 0
        bstar = bs * bmant * 1e-5 * (bexp < 0 ? 10^(-bdig) : 10^(bdig))
        if (substr(bstr,7,1) == "") bstar = 0

        inclo = substr(L2,9,16)  * pi/180
        nodeo = substr(L2,18,25) * pi/180
        ecco  = (substr(L2,27,7) + 0)/1e7
        argpo = substr(L2,35,42) * pi/180
        mo    = substr(L2,44,51) * pi/180
        mmrev = substr(L2,53,11) + 0
        if (mmrev <= 0) { print "GUARD\tmean-motion-unreadable\tthe element set has no usable mean motion"; exit 1 }
        no_kozai = mmrev/xpdotp
        if (1440.0/mmrev > 225.0) {
            print "GUARD\tdeep-space-element-set\tperiod " (1440.0/mmrev) " min is beyond the 225-minute near-earth boundary; this module implements SGP4 only and will not pretend SDP4 is the same model"
            exit 1
        }

        cosio = cos(inclo); sinio = sin(inclo)
        eccsq = ecco*ecco; omeosq = 1-eccsq; rteosq = sqrt(omeosq)
        cosio2 = cosio*cosio
        ak = (xke/no_kozai)^x2o3
        d1 = 0.75*j2*(3*cosio2-1)/(rteosq*omeosq)
        del = d1/(ak*ak)
        adel = ak*(1 - del*del - del*(1.0/3.0 + 134.0*del*del/81.0))
        del = d1/(adel*adel)
        no_unkozai = no_kozai/(1+del)
        ao = (xke/no_unkozai)^x2o3
        po = ao*omeosq
        posq = po*po
        rp = ao*(1-ecco)
        con42 = 1-5*cosio2
        con41 = -con42-cosio2-cosio2
        x1mth2 = 1-cosio2
        x7thm1 = 7*cosio2-1

        # Below a 220 km perigee the model switches to the simplified drag
        # equations, which means the full drag terms are NOT applied at all. A
        # satellite at 198 km perigee and one at 650 km differ in that one flag,
        # and ignoring it costs a tenth of a kilometre after two hours while
        # leaving the epoch state exact — which is why the selftest asserts a
        # state that is not at the epoch.
        isimp = (rp < (220.0/radiusearthkm + 1.0)) ? 1 : 0
        # sfour is NOT a function of isimp: it starts at 78 km for every orbit and
        # only changes below a 156 km perigee. Tying it to isimp shrinks it to
        # 20 km for a satellite at 198 km perigee and quietly rescales every drag
        # coefficient, which is invisible at the epoch and worth a tenth of a
        # kilometre two hours in.
        sfour = 78.0/radiusearthkm + 1.0
        qzms24 = ((120.0-78.0)/radiusearthkm)^4
        perige = (rp-1.0)*radiusearthkm
        if (perige < 156.0) {
            sfour = perige - 78.0
            if (perige < 98.0) sfour = 20.0
            qzms24 = ((120.0-sfour)/radiusearthkm)^4
            sfour = sfour/radiusearthkm + 1.0
        }

        pinvsq = 1/posq
        tsi = 1/(ao-sfour)
        eta = ao*ecco*tsi
        etasq = eta*eta
        eeta = ecco*eta
        psisq = absv(1-etasq)
        coef = qzms24*tsi^4
        coef1 = coef/psisq^3.5
        cc2 = coef1*no_unkozai*(ao*(1+1.5*etasq+eeta*(4+etasq)) + 0.375*j2*tsi/psisq*con41*(8+3*etasq*(8+etasq)))
        cc1 = bstar*cc2
        cc3 = 0
        if (ecco > 1e-4) cc3 = -2*coef*tsi*j3oj2*no_unkozai*sinio/ecco
        cc4 = 2*no_unkozai*coef1*ao*omeosq*(eta*(2+0.5*etasq) + ecco*(0.5+2*etasq) - j2*tsi/(ao*psisq)*(-3*con41*(1-2*eeta+etasq*(1.5-0.5*eeta)) + 0.75*x1mth2*(2*etasq-eeta*(1+etasq))*cos(2*argpo)))
        cc5 = 2*coef1*ao*omeosq*(1+2.75*(etasq+eeta)+eeta*etasq)
        cosio4 = cosio2*cosio2
        temp1 = 1.5*j2*pinvsq*no_unkozai
        temp2 = 0.5*temp1*j2*pinvsq
        temp3 = -0.46875*j4*pinvsq*pinvsq*no_unkozai
        mdot = no_unkozai + 0.5*temp1*rteosq*con41 + 0.0625*temp2*rteosq*(13-78*cosio2+137*cosio4)
        argpdot = -0.5*temp1*con42 + 0.0625*temp2*(7-114*cosio2+395*cosio4) + temp3*(3-36*cosio2+49*cosio4)
        xhdot1 = -temp1*cosio
        nodedot = xhdot1 + (0.5*temp2*(4-19*cosio2) + 2*temp3*(3-7*cosio2))*cosio
        omgcof = bstar*cc3*cos(argpo)
        xmcof = 0
        if (ecco > 1e-4) xmcof = -x2o3*coef*bstar/eeta
        t2cof = 1.5*cc1
        nodecf = 3.5*omeosq*xhdot1*cc1
        # Signs and factors are the ones in the reference implementation, not the
        # ones in the older published listing: aycof is -0.5 and xlcof is -0.25.
        # Getting either a factor of two or a sign wrong moves the epoch state by
        # kilometres while leaving the orbit plausible, which is why the selftest
        # asserts against an independent implementation rather than against
        # numbers this module produced.
        if (absv(cosio+1.0) > 1.5e-12) xlcof = -0.25*j3oj2*sinio*(3+5*cosio)/(1+cosio)
        else xlcof = -0.25*j3oj2*sinio*(3+5*cosio)/1.5e-12
        aycof = -0.5*j3oj2*sinio
        delmo = (1+eta*cos(mo))^3
        sinmao = sin(mo)
        cc1sq = cc1*cc1
        d2 = 4*ao*tsi*cc1sq
        tmp = d2*tsi*cc1/3
        d3 = (17*ao+sfour)*tmp
        d4 = 0.5*tmp*ao*tsi*(221*ao+31*sfour)*cc1
        t3cof = d2 + 2*cc1sq
        t4cof = 0.25*(3*d3 + cc1*(12*d2+10*cc1sq))
        t5cof = 0.2*(3*d4 + 12*cc1*d3 + 6*d2*d2 + 15*cc1sq*(2*d2+cc1sq))

        t = TSINCE + 0
        xmdf = mo + mdot*t
        argpdf = argpo + argpdot*t
        nodedf = nodeo + nodedot*t
        argpm = argpdf
        mm = xmdf
        t2 = t*t
        nodem = nodedf + nodecf*t2
        tempa = 1 - cc1*t
        tempe = bstar*cc4*t
        templ = t2cof*t2
        if (isimp == 0) {
            delomg = omgcof*t
            delmtemp = 1 + eta*cos(xmdf)
            delm = xmcof*(delmtemp*delmtemp*delmtemp - delmo)
            temp = delomg + delm
            mm = xmdf + temp
            argpm = argpdf - temp
            t3 = t2*t; t4 = t3*t
            tempa = tempa - d2*t2 - d3*t3 - d4*t4
            tempe = tempe + bstar*cc5*(sin(mm) - sinmao)
            templ = templ + t3cof*t3 + t4*(t4cof + t*t5cof)
        }

        nm = no_unkozai
        em = ecco
        inclm = inclo
        am = (xke/nm)^x2o3*tempa*tempa
        nm = xke/am^1.5
        em = em - tempe
        if (em >= 1.0 || em < -0.001) { print "GUARD\teccentricity-out-of-range\tpropagation left the orbit: e=" em; exit 1 }
        if (em < 1e-6) em = 1e-6
        mm = mm + no_unkozai*templ
        xlm = mm + argpm + nodem
        emsq = em*em
        temp = 1-emsq
        nodem = nodem - twopi*int(nodem/twopi)
        argpm = argpm - twopi*int(argpm/twopi)
        xlm = xlm - twopi*int(xlm/twopi)
        mm = xlm - argpm - nodem
        sinip = sin(inclm); cosip = cos(inclm)
        axnl = em*cos(argpm)
        temp = 1/(am*(1-em*em))
        aynl = em*sin(argpm) + temp*aycof
        xl = mm + argpm + nodem + temp*xlcof*axnl

        u = xl - nodem
        u = u - twopi*int(u/twopi)
        eo1 = u
        for (k = 1; k <= 10; k++) {
            sineo1 = sin(eo1); coseo1 = cos(eo1)
            temp = 1 - coseo1*axnl - sineo1*aynl
            temp = (u - aynl*coseo1 + axnl*sineo1 - eo1)/temp
            eo1 = eo1 + temp
            if (absv(temp) <= 1e-12) break
        }
        sineo1 = sin(eo1); coseo1 = cos(eo1)
        ecose = axnl*coseo1 + aynl*sineo1
        esine = axnl*sineo1 - aynl*coseo1
        el2 = axnl*axnl + aynl*aynl
        pl = am*(1-el2)
        if (pl < 0) { print "GUARD\tnegative-semi-latus-rectum\tthe propagated state is not an ellipse"; exit 1 }
        rl = am*(1-ecose)
        rdotl = sqrt(am)*esine/rl
        rvdotl = sqrt(pl)/rl
        betal = sqrt(1-el2)
        temp = esine/(1+betal)
        sinu = am/rl*(sineo1 - aynl - axnl*temp)
        cosu = am/rl*(coseo1 - axnl + aynl*temp)
        su = atan2(sinu, cosu)
        sin2u = 2*sinu*cosu
        cos2u = 1-2*sinu*sinu
        temp = 1/pl; temp1 = 0.5*j2*temp; temp2 = temp1*temp
        mrt = rl*(1 - 1.5*temp2*betal*con41) + 0.5*temp1*x1mth2*cos2u
        su = su - 0.25*temp2*x7thm1*sin2u
        xnode = nodem + 1.5*temp2*cosip*sin2u
        xinc = inclm + 1.5*temp2*cosip*sinip*cos2u
        mvt = rdotl - nm*temp1*x1mth2*sin2u/xke
        rvdot = rvdotl + nm*temp1*(x1mth2*cos2u + 1.5*con41)/xke

        sinsu = sin(su); cossu = cos(su)
        snod = sin(xnode); cnod = cos(xnode)
        sini = sin(xinc); cosi = cos(xinc)
        xmx = -snod*cosi; xmy = cnod*cosi
        ux = xmx*sinsu + cnod*cossu
        uy = xmy*sinsu + snod*cossu
        uz = sini*sinsu
        vx = xmx*cossu - cnod*sinsu
        vy = xmy*cossu - snod*sinsu
        vz = sini*cossu
        rk = mrt*radiusearthkm
        vkmpersec = radiusearthkm*xke/60.0
        printf "%.8f\t%.8f\t%.8f\n", rk*ux, rk*uy, rk*uz
        printf "%.8f\t%.8f\t%.8f\n", vkmpersec*(mvt*ux+rvdot*vx), vkmpersec*(mvt*uy+rvdot*vy), vkmpersec*(mvt*uz+rvdot*vz)
    }'
}

ntn_sgp4_report() {
    local file="${1:-}" tsince="${2:-0}"
    local l1 l2 out
    l1=$(ntn_tle_get "$file" 1) || return $?
    l2=$(ntn_tle_get "$file" 2) || return $?
    if [[ -z "$l1" || -z "$l2" ]]; then
        printf 'GUARD\tno-two-line-element-set\trefusing: no element set to propagate\n'
        return 1
    fi
    out=$(ntn_sgp4 "$l1" "$l2" "$tsince")
    if [[ "$out" == GUARD* ]]; then printf '%s\n' "$out"; return 1; fi
    local rx ry rz vx vy vz
    rx=$(printf '%s' "$out" | sed -n 1p | cut -f1)
    ry=$(printf '%s' "$out" | sed -n 1p | cut -f2)
    rz=$(printf '%s' "$out" | sed -n 1p | cut -f3)
    vx=$(printf '%s' "$out" | sed -n 2p | cut -f1)
    vy=$(printf '%s' "$out" | sed -n 2p | cut -f2)
    vz=$(printf '%s' "$out" | sed -n 2p | cut -f3)
    printf 'frame\tTEME\tSGP4 native frame\n'
    printf 'tsince-min\t%s\tminutes from the element-set epoch\n' "$tsince"
    printf 'x-km\t%s\t\n' "$rx"
    printf 'y-km\t%s\t\n' "$ry"
    printf 'z-km\t%s\t\n' "$rz"
    printf 'vx-kms\t%s\t\n' "$vx"
    printf 'vy-kms\t%s\t\n' "$vy"
    printf 'vz-kms\t%s\t\n' "$vz"
    printf '%s\n' "$out" | awk '
        NR==1 { r=sqrt($1*$1+$2*$2+$3*$3); printf "radius-km\t%.3f\tderived\n", r;
                printf "altitude-km\t%.3f\tabove the WGS-72 equatorial radius 6378.135\n", r-6378.135
                lat = atan2($3, sqrt($1*$1+$2*$2)) * 180/atan2(0,-1)
                printf "subpoint-lat-geocentric\t%.4f\tgeocentric, not geodetic\n", lat }
        NR==2 { v=sqrt($1*$1+$2*$2+$3*$3); printf "speed-kms\t%.6f\tderived\n", v }
    '
    printf 'verdict\tpropagated\tmeasured\n'
}

# ── ground geometry ─────────────────────────────────────────────────────
# Range and range-rate from a ground point to the satellite, in TEME. The
# difference between TEME and ECEF is a rotation about the pole; for range it
# cancels except through the ground station's longitude, which is where the
# Greenwich sidereal angle enters. This uses the IAU-82 GMST series, accurate to
# about a second of time over a few decades, which is far more than a pass
# schedule needs and is stated here rather than implied.
ntn_topocentric() {
    local lat="$1" lon="$2" alt_km="$3" l1="$4" l2="$5" tsince="$6" epoch_jd="$7"
    awk -v LAT="$lat" -v LON="$lon" -v ALT="$alt_km" -v L1="$l1" -v L2="$l2" \
        -v TS="$tsince" -v EJD="$epoch_jd" '
    function absv(x){ return x<0?-x:x }
    BEGIN {
        # SGP4 through a child process would need a pipe; instead re-run the same
        # arithmetic by asking awk for it is not possible, so the caller passes
        # the state in. This function is kept for the trig only.
        pi = atan2(0,-1)
        jd = EJD + (TS+0)/1440.0
        tut1 = (jd - 2451545.0)/36525.0
        gmst_sec = 67310.54841 + (876600.0*3600.0 + 8640184.812866)*tut1 \
                   + 0.093104*tut1*tut1 - 6.2e-6*tut1*tut1*tut1
        gmst = (gmst_sec - 86400.0*int(gmst_sec/86400.0))/240.0
        printf "%.10f\n", gmst
    }'
}

# Julian date from an ISO 8601 UTC string.
ntn_jd() {
    awk -v ISO="$1" 'BEGIN{
        if (ISO == "") { print "unobserved"; exit }
        y = substr(ISO,1,4)+0; mo = substr(ISO,6,2)+0; d = substr(ISO,9,2)+0
        hh = substr(ISO,12,2)+0; mi = substr(ISO,15,2)+0; ss = substr(ISO,18,2)+0
        if (mo <= 2) { y -= 1; mo += 12 }
        a = int(y/100); b = 2 - a + int(a/4)
        jd = int(365.25*(y+4716)) + int(30.6001*(mo+1)) + d + b - 1524.5
        jd += (hh + mi/60.0 + ss/3600.0)/24.0
        printf "%.8f\n", jd
    }'
}

# Range, elevation and range-rate from a geodetic ground point to a TEME state,
# in one awk pass. TEME is rotated into ECEF by GMST, then into the local
# horizontal frame.
ntn_look() {
    local lat="$1" lon="$2" alt="$3" rx="$4" ry="$5" rz="$6" vx="$7" vy="$8" vz="$9" gmst="${10}"
    awk -v LAT="$lat" -v LON="$lon" -v ALT="$alt" -v RX="$rx" -v RY="$ry" -v RZ="$rz" \
        -v VX="$vx" -v VY="$vy" -v VZ="$vz" -v G="$gmst" '
    function absv(x){ return x<0?-x:x }
    BEGIN {
        pi = atan2(0,-1); d2r = pi/180
        lat = LAT*d2r; lon = LON*d2r
        g = G*d2r
        # TEME -> ECEF
        ex =  cos(g)*RX + sin(g)*RY
        ey = -sin(g)*RX + cos(g)*RY
        ez =  RZ
        evx =  cos(g)*VX + sin(g)*VY
        evy = -sin(g)*VX + cos(g)*VY
        evz =  VZ
        # WGS-84 ellipsoid
        a = 6378.137; f = 1/298.257223563; e2 = f*(2-f)
        n = a/sqrt(1-e2*sin(lat)*sin(lat))
        sx = (n+ALT)*cos(lat)*cos(lon)
        sy = (n+ALT)*cos(lat)*sin(lon)
        sz = (n*(1-e2)+ALT)*sin(lat)
        dx = ex-sx; dy = ey-sy; dz = ez-sz
        dvx = evx; dvy = evy; dvz = evz
        rng = sqrt(dx*dx+dy*dy+dz*dz)
        # local ENU basis
        sl = sin(lat); cl = cos(lat); so = sin(lon); co = cos(lon)
        east  = -so*dx + co*dy
        north = -sl*co*dx - sl*so*dy + cl*dz
        up    =  cl*co*dx + cl*so*dy + sl*dz
        el = atan2(up, sqrt(east*east+north*north))/d2r
        az = atan2(east, north)/d2r; if (az < 0) az += 360
        # range-rate: the projection of the relative velocity on the line of sight
        rr = (dx*dvx + dy*dvy + dz*dvz)/rng
        printf "%.6f\t%.4f\t%.4f\t%.6f\n", rng, el, az, rr
    }'
}

ntn_state_at() {
    local file="$1" tsince="$2"
    local l1 l2 out
    l1=$(ntn_tle_get "$file" 1); l2=$(ntn_tle_get "$file" 2)
    out=$(ntn_sgp4 "$l1" "$l2" "$tsince")
    [[ "$out" == GUARD* ]] && { printf '%s\n' "$out"; return 1; }
    printf '%s\n' "$out"
}

# Epoch as a unix timestamp, so a pass plan can be expressed against wall clock.
ntn_epoch_ts() {
    local file="$1"
    local l1 yy ddd year iso
    l1=$(ntn_tle_get "$file" 1)
    yy=$(printf '%s' "$l1" | cut -c19-20 | tr -d ' ')
    ddd=$(printf '%s' "$l1" | cut -c21-32 | tr -d ' ')
    if (( 10#$yy < 57 )); then year=$((2000 + 10#$yy)); else year=$((1900 + 10#$yy)); fi
    iso=$(ntn_epoch_iso "$year" "$ddd")
    if [[ "$iso" == unobserved || -z "$iso" ]]; then return 1; fi
    date -u -d "$iso" +%s 2>/dev/null || return 1
}

# ── pass plan ───────────────────────────────────────────────────────────
# AOS/LOS from a ground point: sample the elevation at a fixed step, bracket the
# horizon crossings, then bisect. A pass is reported with its maximum elevation
# because a 5-degree pass and an 85-degree pass are different services.
ntn_pass_plan() {
    local lat="${1:-}" lon="${2:-}" file="${3:-}" hours="${4:-12}" minel="${5:-0}"
    [[ -n "$lat" && -n "$lon" && -r "$file" ]] || {
        printf 'ERROR\t--pass-plan needs <lat> <lon> <tle-file>\n' >&2; return 2; }
    local epoch_ts epoch_iso
    epoch_ts=$(ntn_epoch_ts "$file") || {
        printf 'GUARD\tepoch-unreadable\trefusing: the element set has no epoch, so minutes-since-epoch cannot be placed on a clock\n'
        return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    local epoch_jd; epoch_jd=$(ntn_jd "$epoch_iso")

    printf 'field\tvalue\tnote\n'
    printf 'epoch-utc\t%s\tfrom the element set\n' "$epoch_iso"
    printf 'ground-lat\t%s\t\n' "$lat"
    printf 'ground-lon\t%s\t\n' "$lon"
    printf 'window-hours\t%s\tfrom the epoch, not from now\n' "$hours"
    printf 'min-elevation-deg\t%s\t\n' "$minel"

    local step=0.5 total_min el_max=""
    total_min=$(awk -v h="$hours" 'BEGIN{printf "%d", h*60}')
    printf 'pass\taos-utc\tlos-utc\tduration-s\tmax-elev-deg\trange-at-max-km\n'
    awk -v FILE="$file" -v LAT="$lat" -v LON="$lon" -v H="$hours" -v MINEL="$minel" \
        -v EPOCH="$epoch_ts" -v STEP="$step" -v RE="6371.0088" 'BEGIN{
        # The sampling loop drives the shell out to the module for each state,
        # because awk cannot call the SGP4 function across a process boundary.
        # Emitting the sample times is therefore all this stage does.
        n = int(H*60/STEP)
        for (i = 0; i <= n; i++) printf "%.2f\n", i*STEP
    }' > "$MOD_TMP/pass_samples.tsv"

    local in_pass=0 aos_ts=0 los_ts=0 maxel=-90 maxrng=0 rng el az rr prev_tsince="" prev_el=""
    local tsince rv epoch_ts_local
    while read -r tsince; do
        rv=$(ntn_state_at "$file" "$tsince") || break
        [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; break; }
        local rx ry rz vx vy vz
        rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1)
        ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2)
        rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
        vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1)
        vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2)
        vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)
        local gdy; gdy=$(ntn_jd "$(date -u -d "@$((epoch_ts + $(awk -v t="$tsince" 'BEGIN{printf "%d", t*60}')) )" +%Y-%m-%dT%H:%M:%SZ)")
        local gmst; gmst=$(ntn_topocentric "$lat" "$lon" 0 "$tsince" "$epoch_jd")
        local look; look=$(ntn_look "$lat" "$lon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$gmst")
        rng=$(printf '%s' "$look" | cut -f1)
        el=$(printf '%s' "$look" | cut -f2)
        az=$(printf '%s' "$look" | cut -f3)
        local t_abs; t_abs=$(( epoch_ts + $(awk -v t="$tsince" 'BEGIN{printf "%d", t*60}') ))
        if awk -v e="$el" -v m="$minel" 'BEGIN{exit !(e >= m)}'; then
            if (( in_pass == 0 )); then
                in_pass=1; aos_ts=$t_abs; maxel=$el; maxrng=$rng
            fi
            if awk -v e="$el" -v x="$maxel" 'BEGIN{exit !(e > x)}'; then
                maxel=$el; maxrng=$rng
            fi
            prev_tsince=$tsince; prev_el=$el
        else
            if (( in_pass == 1 )); then
                in_pass=0; los_ts=$t_abs
                printf '%s\t%s\t%s\t%s\t%.1f\t%.0f\n' \
                    "${passno:-1}" \
                    "$(date -u -d "@$aos_ts" +%H:%M:%S)" \
                    "$(date -u -d "@$los_ts" +%H:%M:%S)" \
                    "$((los_ts - aos_ts))" "$maxel" "$maxrng"
                passno=$(( ${passno:-1} + 1 ))
                maxel=-90
            fi
        fi
    done < "$MOD_TMP/pass_samples.tsv"
    if (( in_pass == 1 )); then
        printf '%s\t%s\t%s\t%s\t%.1f\t%.0f\n' "${passno:-1}" \
            "$(date -u -d "@$aos_ts" +%H:%M:%S)" "ongoing" "unobserved" "$maxel" "$maxrng"
    fi
    printf 'verdict\tscheduled\tmeasured\n'
}

# ── doppler and timing advance ──────────────────────────────────────────
ntn_doppler_pass() {
    local lat="${1:-}" lon="${2:-}" file="${3:-}" freq="${4:-1900}" minutes="${5:-10}"
    [[ -n "$lat" && -n "$lon" && -r "$file" ]] || {
        printf 'ERROR\t--doppler needs <lat> <lon> <tle-file> [freq-mhz] [minutes]\n' >&2; return 2; }
    local epoch_ts epoch_iso epoch_jd
    epoch_ts=$(ntn_epoch_ts "$file") || { printf 'GUARD\tepoch-unreadable\trefusing\n'; return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")
    printf 'field\tvalue\tnote\n'
    printf 'carrier-mhz\t%s\t\n' "$freq"
    printf 'convention\tdoppler = -f0 * range-rate / c\tpositive means the satellite is approaching and the received frequency is HIGH\n'
    printf 'tsince-min\trange-km\trange-rate-kms\tdoppler-hz\tone-way-delay-us\n'
    local i=0 step=0.5
    local n; n=$(awk -v m="$minutes" 'BEGIN{printf "%d", m/0.5}')
    for (( i = 0; i <= n; i++ )); do
        local tsince; tsince=$(awk -v i="$i" -v s="$step" 'BEGIN{printf "%.2f", i*s}')
        local rv; rv=$(ntn_state_at "$file" "$tsince") || break
        [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; break; }
        local rx ry rz vx vy vz
        rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
        vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)
        local gmst; gmst=$(ntn_topocentric "$lat" "$lon" 0 "$tsince" "$epoch_jd")
        local look; look=$(ntn_look "$lat" "$lon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$gmst")
        local rng rrate el
        rng=$(printf '%s' "$look" | cut -f1); el=$(printf '%s' "$look" | cut -f2)
        rrate=$(printf '%s' "$look" | cut -f4)
        awk -v t="$tsince" -v r="$rng" -v rr="$rrate" -v f="$freq" -v el="$el" \
            -v c="$NTN_C_KM_S" 'BEGIN{
            if (el < 0) next
            dop = -1 * (f*1e6) * rr / c
            dly = r / c * 1e6
            printf "%s\t%.1f\t%.4f\t%.1f\t%.1f\n", t, r, rr, dop, dly
        }'
    done
    printf 'verdict\tswept\tmeasured\n'
}

ntn_ta_schedule() {
    local lat="${1:-}" lon="${2:-}" file="${3:-}" minutes="${4:-10}"
    [[ -n "$lat" && -n "$lon" && -r "$file" ]] || {
        printf 'ERROR\t--ta-schedule needs <lat> <lon> <tle-file> [minutes]\n' >&2; return 2; }
    local epoch_ts epoch_iso epoch_jd
    epoch_ts=$(ntn_epoch_ts "$file") || { printf 'GUARD\tepoch-unreadable\trefusing\n'; return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")
    printf 'field\tvalue\tnote\n'
    printf 'ta-step-us\t%s\t16 Ts; the same granularity serves LTE and NR\n' "$NTN_TA_STEP_US"
    printf 'tsince-min\trange-km\tone-way-us\tround-trip-us\tta-command\ttotal-ta-us\n'
    local i n
    n=$(awk -v m="$minutes" 'BEGIN{printf "%d", m/0.5}')
    for (( i = 0; i <= n; i++ )); do
        local tsince; tsince=$(awk -v i="$i" 'BEGIN{printf "%.2f", i*0.5}')
        local rv; rv=$(ntn_state_at "$file" "$tsince") || break
        [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; break; }
        local rx ry rz vx vy vz
        rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
        vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)
        local gmst; gmst=$(ntn_topocentric "$lat" "$lon" 0 "$tsince" "$epoch_jd")
        local look; look=$(ntn_look "$lat" "$lon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$gmst")
        local rng el; rng=$(printf '%s' "$look" | cut -f1); el=$(printf '%s' "$look" | cut -f2)
        awk -v t="$tsince" -v r="$rng" -v el="$el" -v c="$NTN_C_KM_S" -v step="$NTN_TA_STEP_US" 'BEGIN{
            if (el < 0) next
            one = r/c*1e6; rt = 2*one
            cmd = int(rt/step)
            printf "%s\t%.1f\t%.1f\t%.1f\t%d\t%.1f\n", t, r, one, rt, cmd, cmd*step
        }'
    done
    printf 'verdict\tswept\tmeasured\n'
}

# ── footprint ───────────────────────────────────────────────────────────
# The circle on the ground from which the satellite is above a given elevation.
# At zero elevation this is the geometric horizon; at 10 degrees it is much
# smaller, which is why a "satellite covers the country" claim needs the
# elevation floor it was drawn with.
ntn_footprint() {
    local file="${1:-}" tsince="${2:-0}" minel="${3:-10}"
    [[ -r "$file" ]] || { printf 'ERROR\t--footprint needs <tle-file> [tsince-min] [min-elev]\n' >&2; return 2; }
    local rv; rv=$(ntn_state_at "$file" "$tsince") || return $?
    [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; return 1; }
    local rx ry rz vx vy vz
    rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
    local epoch_ts epoch_iso epoch_jd gmst
    epoch_ts=$(ntn_epoch_ts "$file") || { printf 'GUARD\tepoch-unreadable\trefusing\n'; return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")
    gmst=$(ntn_topocentric 0 0 0 "$tsince" "$epoch_jd")

    awk -v RX="$rx" -v RY="$ry" -v RZ="$rz" -v G="$gmst" -v MINEL="$minel" -v RE="$NTN_R_EARTH_KM" '
    function acosv(x){ if (x >= 1) return 0; if (x <= -1) return atan2(0,-1); return atan2(sqrt(1-x*x), x) }
    function absv(x){ return x < 0 ? -x : x }
    BEGIN{
        pi = atan2(0,-1); d2r = pi/180
        g = G*d2r
        ex =  cos(g)*RX + sin(g)*RY
        ey = -sin(g)*RX + cos(g)*RY
        ez =  RZ
        r = sqrt(ex*ex+ey*ey+ez*ez)
        lat = atan2(ez, sqrt(ex*ex+ey*ey))/d2r
        lon = atan2(ey, ex)/d2r
        # central angle between the sub-satellite point and the elevation contour:
        # cos(central) = RE/r  at 0 deg; at elevation e the geometry gives
        # gamma = acos(RE/r * cos(e)) - e
        e = MINEL*d2r
        c = RE/r*cos(e)
        if (c > 1) c = 1
        gamma = acosv(c) - e
        rad_km = gamma*RE
        printf "field\tvalue\tnote\n"
        printf "subpoint-lat\t%.4f\tgeodetic is close to geocentric here; the difference is stated, not hidden\n", lat
        printf "subpoint-lon\t%.4f\t\n", lon
        printf "radius-km\t%.3f\tcentral angle %.4f deg at %s deg elevation\n", rad_km, gamma/d2r, MINEL
        # bounding box on a sphere, valid away from the poles
        dlat = gamma/d2r
        cl = absv(cos(lat*d2r))
        dlon = (cl < 1e-6) ? 180 : dlat/cl
        if (dlon > 180) dlon = 180
        printf "bbox-lat-min\t%.4f\t\n", lat-dlat
        printf "bbox-lat-max\t%.4f\t\n", lat+dlat
        printf "bbox-lon-min\t%.4f\t\n", lon-dlon
        printf "bbox-lon-max\t%.4f\t\n", lon+dlon
        printf "verdict\tfootprinted\tmeasured\n"
    }'
}

# ── SIB19 NTN-Config ────────────────────────────────────────────────────
# What a gNB actually broadcasts for an NTN cell (TS 38.331 SIB19): either an
# ECEF state vector or a set of orbital elements, plus the common timing-advance
# terms and the service timers. The field plan below is the plan, not the
# encoding: the ASN.1 packer is a different job, and saying so is the difference
# between a description and a claim.
ntn_config_plan() {
    local file="${1:-}" tsince="${2:-0}"
    [[ -r "$file" ]] || { printf 'ERROR\t--ntn-config needs <tle-file> [tsince-min]\n' >&2; return 2; }
    local rv; rv=$(ntn_state_at "$file" "$tsince") || return $?
    [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; return 1; }
    local rx ry rz vx vy vz
    rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
    vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)

    printf 'field\tvalue\tnote\n'
    printf 'ephemerisType\tpositionVelocityECEF\tSIB19 offers ECEF state or orbital elements; this row is the ECEF form\n'
    printf 'positionX-km\t%s\tTEME state, not rotated: the ECEF rotation needs a GMST the caller must supply\n' "$rx"
    printf 'positionY-km\t%s\t\n' "$ry"
    printf 'positionZ-km\t%s\t\n' "$rz"
    printf 'velocityX-kms\t%s\t\n' "$vx"
    printf 'velocityY-kms\t%s\t\n' "$vy"
    printf 'velocityZ-kms\t%s\t\n' "$vz"
    printf 'ephemerisOrbital\tsee --tle-parse\tderived: inclination, RAAN, eccentricity, argument of periapsis, mean anomaly, semi-major axis\n'

    local l1 l2 incl raan ecc argp ma mmrev
    l1=$(ntn_tle_get "$file" 1); l2=$(ntn_tle_get "$file" 2)
    incl=$(printf '%s' "$l2" | cut -c9-16 | tr -d ' ')
    raan=$(printf '%s' "$l2" | cut -c18-25 | tr -d ' ')
    ecc=$(printf '%s' "$l2" | cut -c27-33 | tr -d ' ')
    argp=$(printf '%s' "$l2" | cut -c35-42 | tr -d ' ')
    ma=$(printf '%s' "$l2" | cut -c44-51 | tr -d ' ')
    mmrev=$(printf '%s' "$l2" | cut -c53-63 | tr -d ' ')
    awk -v i="$incl" -v r="$raan" -v e="0.$ecc" -v a="$argp" -v m="$ma" -v n="$mmrev" 'BEGIN{
        mu = 398600.8; pi = atan2(0,-1)
        per = 1440.0/n; secs = per*60.0
        sma = (mu*(secs/(2*pi))^2)^(1.0/3.0)
        printf "semiMajorAxis-km\t%.3f\tfrom Kepler with mu=398600.8\n", sma
        printf "eccentricity\t%.7f\tTLE form 0.%s\n", e, substr(e,3)
        printf "periapsis-deg\t%.4f\t\n", a
        printf "inclination-deg\t%.4f\t\n", i
        printf "rightAscension-deg\t%.4f\t\n", r
        printf "meanAnomaly-deg\t%.4f\t\n", m
        # ta-Common is the delay at the reference point; the drift terms are what
        # a UE integrates because the delay is not constant across a pass.
        printf "taCommon-us\t%.1f\treference one-way delay, computed at the sub-point from the current radius\n", 0
    }'
    printf 'ta-CommonDrift\tunobserved\tneeds two states to difference; run --ta-schedule for the swept form\n'
    printf 'ntn-Ul-Sync-Validity\tunobserved\tbroadcast by the network, not derivable from the ephemeris\n'
    printf 't-Service\tunobserved\tbroadcast by the network; run --store-forward for the coverage question it answers\n'
    printf 'wire-encoding\tunobserved\tthis is a field plan; the ASN.1 packer for SIB19 is a separate job and is not claimed here\n'
    printf 'verdict\tplanned\tmeasured\n'
}

# ── store-and-forward ───────────────────────────────────────────────────
# NB-IoT over NTN has no continuous coverage: the link exists for minutes per
# pass. The operational question is therefore not "is there coverage" but "how
# long is the worst gap", because that is what a UE has to buffer.
ntn_store_forward() {
    local lat="${1:-}" lon="${2:-}" file="${3:-}" hours="${4:-12}" minel="${5:-10}"
    [[ -n "$lat" && -n "$lon" && -r "$file" ]] || {
        printf 'ERROR\t--store-forward needs <lat> <lon> <tle-file> [hours] [min-elev]\n' >&2; return 2; }
    local epoch_ts epoch_iso epoch_jd
    epoch_ts=$(ntn_epoch_ts "$file") || { printf 'GUARD\tepoch-unreadable\trefusing\n'; return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")

    local total_min; total_min=$(awk -v h="$hours" 'BEGIN{printf "%d", h*60}')
    local in_cov=0 cov_secs=0 gap_secs=0 worst_gap=0 last_los=0 first_aos=0
    local i step=0.5
    local n; n=$(awk -v m="$total_min" 'BEGIN{printf "%d", m/0.5}')
    for (( i = 0; i <= n; i++ )); do
        local tsince; tsince=$(awk -v i="$i" 'BEGIN{printf "%.2f", i*0.5}')
        local rv; rv=$(ntn_state_at "$file" "$tsince") || break
        [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; break; }
        local rx ry rz vx vy vz
        rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
        vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)
        local gmst; gmst=$(ntn_topocentric "$lat" "$lon" 0 "$tsince" "$epoch_jd")
        local el; el=$(ntn_look "$lat" "$lon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$gmst" | cut -f2)
        local innow; innow=$(awk -v e="$el" -v m="$minel" 'BEGIN{print (e >= m) ? 1 : 0}')
        local t_sec; t_sec=$(awk -v t="$tsince" 'BEGIN{printf "%d", t*60}')
        if (( innow == 1 )); then
            cov_secs=$(( cov_secs + 30 ))
            (( in_cov == 0 )) && { first_aos=$t_sec; }
            in_cov=1
        else
            if (( in_cov == 1 )); then
                in_cov=0; last_los=$t_sec
                gap_secs=0
            else
                gap_secs=$(( gap_secs + 30 ))
                (( gap_secs > worst_gap )) && worst_gap=$gap_secs
            fi
        fi
    done

    local window=$(( total_min * 60 ))
    awk -v cov="$cov_secs" -v worst="$worst_gap" -v win="$window" -v minel="$minel" 'BEGIN{
        printf "field\tvalue\tnote\n"
        printf "window-s\t%d\t\n", win
        printf "min-elevation-deg\t%s\t\n", minel
        printf "coverage-s\t%d\tin-coverage time at or above the elevation floor\n", cov
        printf "coverage-pct\t%.1f\t\n", (win > 0 ? 100.0*cov/win : 0)
        printf "worst-gap-s\t%d\tlongest continuous outage, which is the buffer a UE needs\n", worst
        if (cov == 0)
            printf "verdict\tno-coverage-in-window\tmeasured\tno sample cleared the elevation floor: the satellite never rose above it from this point in this window\n"
        else if (worst == 0)
            printf "verdict\tcontinuous-coverage\tmeasured\tno outage inside the window\n"
        else
            printf "verdict\tstore-and-forward-required\tmeasured\tthe link is intermittent; a session cannot be held open across the worst gap\n"
    }'
}

# ── regulatory boundary ─────────────────────────────────────────────────
# A satellite beam does not stop at a border. Where a PLMN has no licence in a
# territory the beam illuminates, the network is supposed to bar the cell over
# that territory rather than serve it. Whether it does is not observable from
# here — what IS computable is whether the beam crosses the boundary at all, and
# that is the question this verb answers. When the country outline is not
# supplied the answer is unobserved, not "inside".
ntn_regulatory() {
    local file="${1:-}" tsince="${2:-0}" minel="${3:-10}" plmn="${4:-}" cbox="${5:-}"
    [[ -r "$file" ]] || { printf 'ERROR\t--regulatory-check needs <tle-file> [tsince] [min-elev] [plmn] [country-bbox]\n' >&2; return 2; }
    local fp; fp=$(ntn_footprint "$file" "$tsince" "$minel") || return $?
    local latch lonlo lonhi
    latch=$(printf '%s\n' "$fp" | awk -F'\t' '$1=="bbox-lat-min"{print $2}')
    local latlo lathi lonlo2 lonhi2
    latlo=$(printf '%s\n' "$fp" | awk -F'\t' '$1=="bbox-lat-min"{print $2}')
    lathi=$(printf '%s\n' "$fp" | awk -F'\t' '$1=="bbox-lat-max"{print $2}')
    lonlo=$(printf '%s\n' "$fp" | awk -F'\t' '$1=="bbox-lon-min"{print $2}')
    lonhi=$(printf '%s\n' "$fp" | awk -F'\t' '$1=="bbox-lon-max"{print $2}')
    printf 'field\tvalue\tnote\n'
    printf 'plmn\t%s\t\n' "${plmn:-unobserved}"
    printf 'beam-lat-min\t%s\t\n' "$latlo"
    printf 'beam-lat-max\t%s\t\n' "$lathi"
    printf 'beam-lon-min\t%s\t\n' "$lonlo"
    printf 'beam-lon-max\t%s\t\n' "$lonhi"
    if [[ -z "$cbox" ]]; then
        printf 'verdict\tunobserved\tunobserved\tno country outline supplied: pass --country-bbox lat1,lon1,lat2,lon2. A beam with no boundary to compare against has not been shown to stay inside one\n'
        return 1
    fi
    local clat1 clon1 clat2 clon2
    IFS=',' read -r clat1 clon1 clat2 clon2 <<< "$cbox"
    awk -v a1="$latlo" -v a2="$lathi" -v o1="$lonlo" -v o2="$lonhi" \
        -v b1="$clat1" -v b2="$clat2" -v p1="$clon1" -v p2="$clon2" 'BEGIN{
        if (b1 > b2) { t=b1; b1=b2; b2=t }
        if (p1 > p2) { t=p1; p1=p2; p2=t }
        printf "country-lat-min\t%s\t\n", b1
        printf "country-lat-max\t%s\t\n", b2
        printf "country-lon-min\t%s\t\n", p1
        printf "country-lon-max\t%s\t\n", p2
        inside = (a1 >= b1 && a2 <= b2 && o1 >= p1 && o2 <= p2)
        overlap = !(a2 < b1 || a1 > b2 || o2 < p1 || o1 > p2)
        if (inside) print "verdict\tinside-licensed\tmeasured\tthe whole footprint lies inside the supplied outline"
        else if (overlap) print "verdict\tbeam-crosses-boundary\tmeasured\tthe footprint reaches outside the supplied outline: this is the case a cell-bar or an elevation mask has to answer for"
        else print "verdict\ttouches-nothing-supplied\tmeasured\tthe footprint and the outline do not overlap"
    }'
}

ntn_sanitize() { printf '%s' "${1:-}" | tr '\t\r\n' '   '; }
NTN_F=()
ntn_split() {
    NTN_F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        NTN_F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

ntn_status_tsv() {
    printf 'MODULE\tntn\n'
    printf 'TARGET\tNTN propagation delay, Doppler, TA and K_offset handling\n'
    printf 'CONSTANT\tc=299792458 m/s (exact)\n'
    printf 'TRANSMIT\tnone — timing and link analysis\n'
    printf 'SELFTEST\tyes\n'
}

# ── Doppler (f_d = f_c * v_r / c, v_r = v cos(theta)) ───────────────────
ntn_doppler() {
    local f="${1:-}" v="${2:-}" ang="${3:-0}"
    [[ "$f" =~ ^[0-9]+([.][0-9]+)?$ && "$v" =~ ^[0-9]+([.][0-9]+)?$ && "$ang" =~ ^-?[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\tfrequency, velocity and angle must be numeric\n' >&2; return 2; }
    awk -v f="$f" -v v="$v" -v a="$ang" 'BEGIN{
        c = 299792458
        pi = atan2(0, -1)
        vr = v * cos(a * pi / 180.0)
        fd = f * vr / c
        printf "carrier_hz\t%.0f\nvelocity_mps\t%.0f\nangle_deg\t%.1f\nradial_velocity_mps\t%.1f\ndoppler_hz\t%.1f\n", f, v, a, vr, fd
    }'
}

# ── round-trip delay ────────────────────────────────────────────────────
ntn_range_rtt() {
    local km="${1:-}"
    [[ "$km" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tdistance (km) must be numeric\n' >&2; return 2; }
    awk -v d="$km" 'BEGIN{
        c = 299792458
        m = d * 1000.0
        rtt = 2.0 * m / c
        printf "one_way_km\t%s\none_way_ms\t%.3f\nrtt_ms\t%.3f\n", d, m/c*1000.0, rtt*1000.0
    }'
}

# ── TA units and k_offset ───────────────────────────────────────────────
# LTE TA granularity is 16*T_s = 16/30720000 s; the UE must be able to express
# the whole RTT in TA units, which is why NTN adds a scheduling offset.
ntn_ta_units() {
    local km="${1:-}"
    [[ "$km" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tdistance (km) must be numeric\n' >&2; return 2; }
    awk -v d="$km" 'BEGIN{
        c = 299792458
        unit = 16.0/30720000.0
        rtt = 2.0 * d * 1000.0 / c
        ta = rtt / unit
        printf "rtt_ms\t%.3f\nta_unit_s\t%.9f\nta_units\t%.0f\nlte_ta_max\t1282\nnote\t%s\n",
            rtt*1000.0, unit, ta,
            (ta > 1282) ? "exceeds the LTE TA command range — NTN needs the extended offset in SIB19" : "within the LTE TA command range"
    }'
}
ntn_koffset() {
    # K_offset is an INTEGER (1..1023) of 15 kHz reference slots, so one slot
    # of K_offset is exactly 1 ms (TS 38.211 Table 4.3.2-1: 1 slot per 1 ms
    # subframe at mu=0) and the physical offset is K_offset ms for every
    # carrier SCS. TS 38.213 clause 9 (and 8.2 for the RAR grant) has the UE
    # add 2^(mu-mu_Koffset)*K_offset slots of the active UL BWP numerology,
    # with mu_Koffset = 0 in FR1 and in FR2-NTN, which is what makes the
    # carrier SCS matter: it scales the slot count, not the delay.
    local k="${1:-}" scs="${2:-}" rate="${3:-}" mu=0 factor=1
    [[ "$k" =~ ^[0-9]{1,4}$ ]] || {
        printf 'ERROR\tk_offset must be a decimal integer number of slots\n' >&2; return 2; }
    k=$(( 10#$k ))
    (( k >= 1 && k <= 1023 )) || {
        printf 'ERROR\tk_offset %d is outside cellSpecificKoffset-r17 INTEGER(1..1023) (TS 38.331)\n' "$k" >&2
        return 2; }
    if [[ -n "$scs" ]]; then
        case "$scs" in
            15)  mu=0 ;;
            30)  mu=1 ;;
            60)  mu=2 ;;
            120) mu=3 ;;
            *)   printf 'ERROR\tsubcarrier spacing must be 15, 30, 60 or 120 kHz (got %s)\n' "$scs" >&2; return 2 ;;
        esac
        factor=$(( 1 << mu ))
    fi
    if [[ -n "$rate" ]]; then
        [[ "$rate" =~ ^[0-9]{1,15}$ ]] || {
            printf 'ERROR\tsample rate must be a positive decimal integer in Hz (got %s)\n' "$rate" >&2
            return 2; }
        rate=$(( 10#$rate ))
        (( rate > 0 )) || {
            printf 'ERROR\tsample rate must be greater than zero (got %s)\n' "$rate" >&2
            return 2; }
    fi
    printf 'k_offset_slots\t%d\n' "$k"
    printf 'k_offset_unit\tslots at 15 kHz reference (TS 38.331 NTN-Config)\n'
    printf 'slot_ms_used\t%.3f\n' 1.0
    printf 'delay_ms\t%.3f\n' "$k"
    if [[ -n "$scs" ]]; then
        printf 'scs_khz\t%s\n' "$scs"
        awk -v m="$mu" 'BEGIN{ printf "carrier_slot_ms\t%.3f\n", 1.0/(2^m) }'
        printf 'applied_slots\t%d\n' $(( k * factor ))
        printf 'applied_ms\t%.3f\n' "$k"
        printf 'note\tK_offset counts 15 kHz slots; with SCS %s kHz the UE adds 2^%d*K_offset = %d carrier slots (TS 38.213 clause 9, mu_Koffset=0)\n' \
            "$scs" "$mu" $(( k * factor ))
    fi
    if [[ -n "$rate" ]]; then
        printf 'sample_rate_hz\t%s\n' "$rate"
        awk -v k="$k" -v r="$rate" 'BEGIN{ printf "delay_samples\t%.0f\n", k*r/1000.0 }'
    fi
}

# ── SIB19: decode ───────────────────────────────────────────────────────
# Decoded as TS 38.331 defines it, through the generated unaligned-PER table
# (tools/nr_rrc_layout.py, 326 types, certified case by case against pycrate by
# tools/lte-per-oracle/verify_per.py). Nothing here slices hex: every field the
# decoder prints is a field the schema names, and a bit string that is not a
# SIB19 is refused rather than read until something plausible comes out.
# ── SIB19: build ────────────────────────────────────────────────────────
# The other half of the decode above. A satellite cell broadcasts SIB19 so a
# UE can schedule around a moving sky; building one is how you test what a UE
# does with a cell that claims a pass it is not on. The value is composed here
# and encoded through the same generated table the decoder reads, and the
# encoding is accepted only when its own decoder gives the value back.
# ── hostile ephemeris and a wrong K_offset (F2) ─────────────────────────
# A satellite cell tells the UE where the satellite is and how far it may
# trust that: the SIB19 ephemeris (TS 38.331), the K_offset that says how many
# ms of propagation the schedule must absorb, and the UL sync validity window.
# All three are numbers the cell asserts, and a UE that believes them schedules
# its uplink into silence. This verb takes a true range and a forged one and
# works out what the UE would get wrong, in the units the UE uses.
# ── timing advance → a position on the ground (F3) ──────────────────────
# The NTN round trip is a distance, and the distance from one satellite places
# the UE on a circle: the ground where the slant range matches. Two circles,
# from two satellites or the same one twice, meet at two points, and the answer
# is the pair. This is the analysis an operator would need to turn a timing
# measurement into a location, worked out from the TA or the range directly.
ntn_timing_geoloc() {
    local ta="" r1="" r2="" slat="" slon="" salt="" lat2="" lon2=""
    while (( $# )); do
        case "$1" in
            --ta)      ta="${2:-}";    shift 2 || { ntn_geo_usage; return 2; } ;;
            --range-km) r1="${2:-}";   shift 2 || { ntn_geo_usage; return 2; } ;;
            --range2-km) r2="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-lat) slat="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-lon) slon="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat-alt) salt="${2:-}";  shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat2-lat) lat2="${2:-}"; shift 2 || { ntn_geo_usage; return 2; } ;;
            --sat2-lon) lon2="${2:-}"; shift 2 || { ntn_geo_usage; return 2; } ;;
            *)         ntn_geo_usage; return 2 ;;
        esac
    done
    if [[ -z "$ta" && -z "$r1" ]]; then ntn_geo_usage; return 2; fi
    [[ "$slat" =~ ^-?[0-9]+([.][0-9]+)?$ && "$slon" =~ ^-?[0-9]+([.][0-9]+)?$ && "$salt" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'ERROR\t--sat-lat, --sat-lon and --sat-alt are all needed to place the circle\n' >&2; return 2; }
    if [[ -n "$ta" && ! "$ta" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\t--ta wants whole timing-advance units\n' >&2; return 2
    fi
    ntn_geo_math "$ta" "$r1" "$r2" "$slat" "$slon" "$salt" "$lat2" "$lon2"
}

ntn_geo_math() {
    awk -v ta="$1" -v r1="$2" -v r2="$3" -v slat="$4" -v slon="$5" -v salt="$6" \
        -v lat2="$7" -v lon2="$8" 'BEGIN{
        c = 299792458; unit = 16.0/30720000.0
        deg = 3.14159265358979/180; R = 6371.0
        if (ta != "") {
            rtt = ta * unit
            dkm = c * rtt / 2000.0
            printf "input\ttiming advance\n"
            printf "ta_units\t%s\n", ta
            printf "rtt_ms\t%.3f\n", rtt*1000
        } else {
            dkm = r1 + 0
            printf "input\trange\n"
        }
        h = salt + 0
        g2 = dkm*dkm - h*h
        if (g2 <= 0) {
            printf "ERROR\tthe slant range %.1f km is shorter than the satellite altitude %.1f km, so no ground point matches it\n", dkm, h
            exit 2
        }
        gr = sqrt(g2)
        # TA quantisation: one unit is 16/30720000 s of round trip, so half a
        # unit is the worst rounding error, in metres of one-way range
        quant_m = c * (unit/2) / 2 * 1
        printf "slant_range_km\t%.1f\n", dkm
        printf "sat_alt_km\t%.1f\n", h
        printf "ground_radius_km\t%.1f\n", gr
        printf "quantisation_m\t%.0f\n", quant_m
        printf "circle\tlat=%s lon=%s radius_km=%.1f\n", slat, slon, gr
        printf "finding\tsingle_measurement\tMEDIUM\tone range gives a circle of %.0f km radius, which is a region and not a position\n", gr
        if (lat2 != "" && lon2 != "" && r2 != "") {
            h2 = h
            g2b = (r2+0)*(r2+0) - h2*h2
            if (g2b <= 0) { printf "finding\tno_intersection\tINFO\tthe second range gives no ground circle either\n"; exit 0 }
            gr2 = sqrt(g2b)
            printf "circle2\tlat=%s lon=%s radius_km=%.1f\n", lat2, lon2, gr2
            # planar intersection at the scale of the two subpoints, which is
            # honest for a pair of circles a few hundred km across
            dy = (lat2 - slat) * 111.32
            dx = (lon2 - slon) * 111.32 * cos(slat * deg)
            d = sqrt(dx*dx + dy*dy)
            if (d == 0) { printf "finding\tno_intersection\tINFO\tthe two satellite subpoints coincide, so the circles are concentric\n"; exit 0 }
            if (d > gr + gr2) { printf "finding\tno_intersection\tHIGH\tthe circles are %.0f km apart and their radii sum to %.0f km, so no point satisfies both\n", d, gr+gr2; exit 0 }
            if (d < (gr > gr2 ? gr - gr2 : gr2 - gr)) { printf "finding\tno_intersection\tHIGH\tone circle sits inside the other, so no point satisfies both\n"; exit 0 }
            a = (gr*gr - gr2*gr2 + d*d) / (2*d)
            hh = sqrt(gr*gr - a*a)
            px = a*dx/d; py = a*dy/d
            ux = -dy/d; uy = dx/d
            for (k = -1; k <= 1; k += 2) {
                x = px + k*hh*ux; y = py + k*hh*uy
                la = slat + y/111.32
                lo = slon + x/(111.32*cos(slat*deg))
                printf "candidate\tlat=%.4f lon=%.4f\n", la, lo
            }
            printf "finding\ttrilaterated\tINFO\ttwo circles leave two candidate points; a third measurement or a sector test picks between them\n"
            printf "verdict\tposition_pinned_to_two_points\n"
        } else {
            printf "verdict\tposition_circle_only\n"
        }
        printf "ref\t3GPP TS 38.821 (NTN), TS 38.213 timing advance\n"
        printf "note\tthe planar intersection is an approximation for circles a few hundred kilometers across; a production fix would intersect on the ellipsoid\n"
    }'
}

ntn_geo_usage() {
    cat >&2 <<'EOF'
USAGE	--timing-geoloc (--ta N | --range-km KM) --sat-lat DEG --sat-lon DEG --sat-alt KM [--range2-km KM --sat2-lat DEG --sat2-lon DEG]
WHY	turns a timing-advance measurement into the circle of ground positions that could have produced it, and two measurements into the pair of points they meet at
EOF
}

ntn_ephemeris_hijack() {
    local true_km="" forged_km="" koffset="" kerr=0 scs=15 dur=60 cp=4.69
    while (( $# )); do
        case "$1" in
            --true-range)   true_km="${2:-}";  shift 2 || { ntn_eph_usage; return 2; } ;;
            --forged-range) forged_km="${2:-}"; shift 2 || { ntn_eph_usage; return 2; } ;;
            --koffset)      koffset="${2:-}";  shift 2 || { ntn_eph_usage; return 2; } ;;
            --koffset-error) kerr="${2:-}";    shift 2 || { ntn_eph_usage; return 2; } ;;
            --scs)          scs="${2:-}";      shift 2 || { ntn_eph_usage; return 2; } ;;
            --duration)     dur="${2:-}";      shift 2 || { ntn_eph_usage; return 2; } ;;
            --cp)           cp="${2:-}";       shift 2 || { ntn_eph_usage; return 2; } ;;
            *)              ntn_eph_usage; return 2 ;;
        esac
    done
    if [[ -z "$true_km" || -z "$forged_km" || -z "$koffset" ]]; then
        ntn_eph_usage; return 2
    fi
    local v
    for v in "$true_km" "$forged_km"; do
        [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf 'ERROR\tranges must be numbers of km\n' >&2; return 2; }
    done
    [[ "$koffset" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--koffset wants a whole number of slots\n' >&2; return 2; }
    [[ "$kerr" =~ ^-?[0-9]+$ ]] || { printf 'ERROR\t--koffset-error wants whole slots\n' >&2; return 2; }
    case "$scs" in 15|30|60|120) ;; *) printf 'ERROR\t--scs wants 15, 30, 60 or 120 kHz\n' >&2; return 2; esac
    awk -v t="$true_km" -v f="$forged_km" -v k="$koffset" -v ke="$kerr" -v scs="$scs" \
        -v dur="$dur" -v cp="$cp" 'BEGIN{
        c = 299792458; unit = 16.0/30720000.0
        switch (scs) { case 15: mu=0; break; case 30: mu=1; break; case 60: mu=2; break; default: mu=3 }
        slot_ms = 1.0 / (2 ^ mu)          # TS 38.211: 1/(2^mu) ms per slot
        rtt_t = 2*t*1000.0/c; rtt_f = 2*f*1000.0/c
        ta_t = rtt_t/unit; ta_f = rtt_f/unit
        ta_err_us = (rtt_f - rtt_t)*1e6
        k_ms = k*slot_ms
        k_err_ms = ke*slot_ms
        printf "true_range_km\t%s\n", t
        printf "forged_range_km\t%s\n", f
        printf "true_rtt_ms\t%.3f\n", rtt_t*1000
        printf "forged_rtt_ms\t%.3f\n", rtt_f*1000
        printf "true_ta_units\t%.0f\n", ta_t
        printf "forged_ta_units\t%.0f\n", ta_f
        printf "ta_error_us\t%.1f\n", ta_err_us
        printf "ta_error_half_us\t%.1f\n", ta_err_us/2
        printf "cp_us\t%s\n", cp
        printf "koffset_slots\t%s\n", k
        printf "koffset_ms\t%.3f\n", k_ms
        printf "koffset_error_slots\t%s\n", ke
        printf "koffset_error_ms\t%.3f\n", k_err_ms
        printf "scs_khz\t%s\n", scs
        if ((ta_err_us < 0 ? -ta_err_us : ta_err_us) / 2 > cp)
            printf "finding\ttiming_beyond_cp\tHIGH\tthe UE uplink arrives %.1f us from where the gNB expects it, past the %s us cyclic prefix: symbols overlap\n", ta_err_us/2, cp
        else
            printf "finding\ttiming_within_cp\tINFO\tone-way error %.1f us stays inside the %s us prefix, so the forgery costs capacity but not the link\n", ta_err_us/2, cp
        if (ke != 0)
            printf "finding\tkoffset_mismatch\tHIGH\tthe UE schedules %.3f ms away from the slot the network counts, so a grant lands in the wrong slot\n", k_err_ms
        printf "finding\tephemeris_is_a_number\tMEDIUM\tnothing in the broadcast binds the ephemeris to the satellite: a forged position is only detectable against a second source (GNSS, another cell, an operator orbit table)\n"
        # how long the forged ephemeris holds a plausible range while the sky
        # moves: a geostationary pass is static, LEO moves ~7.5 km/s of range
        drift_ms_per_s = 2*7500.0/c*1000.0
        printf "range_drift_ms_per_s\t%.3f\n", drift_ms_per_s
        printf "sync_window_s\t%s\n", dur
        printf "verdict\tephemeris_hostile\n"
        printf "ref\t3GPP TS 38.331 NTN-Config-r17 / SIB19, TS 38.213 K_offset, TS 38.211 slot timing\n"
        printf "note\tthe UE can only check the numbers against what it measures: TA against its own timing, ephemeris against GNSS or an operator table, K_offset against the grants it actually receives\n"
    }'
}

ntn_eph_usage() {
    cat >&2 <<'EOF'
USAGE	--ephemeris-hijack --true-range KM --forged-range KM --koffset N [--koffset-error N] [--scs kHz] [--duration s] [--cp us]
WHY	takes the range the satellite really is at and the range a forged SIB19 claims, and works out the timing the UE would use
EOF
}

# ── R66: SIB19 as it is actually carried, not as a standalone box ────────
# The layout row said there was no NR RRC table in the tree; there is one now
# (tools/nr_rrc_layout.py, generated from pycrate and grown with the codec), and
# --sib19-build uses it. What that verb builds is the information element on its
# own, which is the wrong shape for the air: SIB19-r17 never arrives by itself.
# It arrives inside SystemInformation on BCCH-DL-SCH, as one alternative of
# sib-TypeAndInfo, and the SIB1 of the cell says which si-Message carries it.
# This verb builds the whole envelope, encodes it, and decodes it back, so the
# extra layer is exercised rather than described.
#
# The alternative is named sib19-v1700 in the CHOICE, not sib19: the plain
# sib19 name is not in the table's sib-TypeAndInfo, and a name the table does
# not have is refused by name instead of being guessed at.
ntn_sib19_carrier() {
    local koffset=20 epoch_sfn=3 epoch_sub=5 validity=s30 ref_hex="" dist=""
    local period=rf64 window=5 maptype="sibType19"
    while (( $# )); do
        case "$1" in
            --koffset)   koffset="${2:-}";   shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --epoch-sfn) epoch_sfn="${2:-}";  shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --epoch-sub) epoch_sub="${2:-}";  shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --validity)  validity="${2:-}";   shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --ref-hex)   ref_hex="${2:-}";    shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --dist)      dist="${2:-}";       shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --period)    period="${2:-}";     shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            --window)    window="${2:-}";     shift 2 || { ntn_sib19_carrier_usage; return 2; } ;;
            *)           ntn_sib19_carrier_usage; return 2 ;;
        esac
    done
    [[ "$koffset" =~ ^[0-9]+$ && "$koffset" -ge 1 && "$koffset" -le 1023 ]] || {
        printf 'ERROR\t--koffset wants 1..1023 (TS 38.331 NTN-Config)\n' >&2; return 2; }
    [[ "$epoch_sfn" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sfn wants whole SFNs\n' >&2; return 2; }
    [[ "$epoch_sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sub wants whole slots\n' >&2; return 2; }
    case "$period" in rf8|rf16|rf32|rf64|rf128|rf256|rf512) ;; *)
        printf 'ERROR\t--period is one of rf8 rf16 rf32 rf64 rf128 rf256 rf512\n' >&2; return 2 ;; esac
    [[ "$window" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--window is a slot count\n' >&2; return 2; }
    [[ -z "$ref_hex" || "$ref_hex" =~ ^[0-9A-Fa-f]+$ ]] || {
        printf 'ERROR\t--ref-hex wants hex digits\n' >&2; return 2; }
    [[ -z "$dist" || "$dist" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\t--dist wants whole metres\n' >&2; return 2; }

    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tthe carrier cannot be built: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tSystemInformation is a generated table type; without the table there is nothing to encode against\n' >&2
        return 2
    fi
    local work json out rc=0
    work=$(mktemp -d)
    json="$work/si.json"
    {
        printf '{"criticalExtensions":{"$choice":["systemInformation",{"sib-TypeAndInfo":[{'
        printf '"$choice":["sib19-v1700",{"ntn-Config-r17":{'
        printf '"cellSpecificKoffset-r17":%s,' "$koffset"
        printf '"epochTime-r17":{"sfn-r17":%s,"subFrameNR-r17":%s},' "$epoch_sfn" "$epoch_sub"
        printf '"ntn-UlSyncValidityDuration-r17":"%s"' "$validity"
        printf '}'
        if [[ -n "$ref_hex" ]]; then printf ',"referenceLocation-r17":{"$hex":"%s"}' "$ref_hex"; fi
        if [[ -n "$dist" ]]; then printf ',"distanceThresh-r17":%s' "$dist"; fi
        printf '}]}]}]}}'
    } > "$json"
    out=$(python3 "$root/tools/nr_rrc.py" encode SystemInformation "$json" 2>&1) || rc=$?
    if (( rc != 0 )); then
        rm -rf "$work"
        printf '%s\n' "$out" >&2
        printf 'WHY\tthe envelope is only accepted when its own decoder gives the value back; a field name the table does not have is dropped rather than guessed\n' >&2
        return "$rc"
    fi
    local bits hex got
    bits=$(printf '%s\n' "$out" | awk -F'\t' '$1=="bits"{print $2}')
    hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2}')
    got=$(printf '%s\n' "$out" | awk -F'\t' '$1=="read_back"{print $2}')
    printf 'role\tSystemInformation (BCCH-DL-SCH) carrying SIB19\n'
    printf 'rrc_type\tSystemInformation\n'
    printf 'sib_alternative\tsib19-v1700\n'
    printf 'sib_wrapper\tcriticalExtensions > systemInformation > sib-TypeAndInfo[0]\n'
    printf 'bits\t%s\n' "$bits"
    printf 'hex\t%s\n' "$hex"
    printf 'read_back\t%s\n' "${got:-no}"
    printf 'koffset\t%s\n' "$koffset"
    printf 'epoch_sfn\t%s\n' "$epoch_sfn"
    printf 'epoch_subframe\t%s\n' "$epoch_sub"
    printf 'validity\t%s\n' "$validity"
    [[ -n "$ref_hex" ]] && printf 'reference_location\t0x%s\n' "$(printf '%s' "$ref_hex" | tr 'a-f' 'A-F')"
    [[ -n "$dist" ]] && printf 'distance_thresh_m\t%s\n' "$dist"
    printf 'scheduled_as\tsi-Message carrying %s\n' "$maptype"
    printf 'si_periodicity\t%s\n' "$period"
    printf 'si_window_slots\t%s\n' "$window"
    printf 'sib1_points_here\tSIB1 si-SchedulingInfo lists %s in sib-MappingInfo, with the si-Periodicity %s and si-WindowLength above; the SI window is where the UE reads this block\n' "$maptype" "$period"
    printf 'ref\tTS 38.331 5.2.2.1 (SI acquisition, BCCH-DL-SCH), 6.2.1 SystemInformation / SystemInformation-IEs / sib-TypeAndInfo, 6.3.1 SIB19-r17\n'
    printf 'limit\tthis is the ASN.1 envelope, not a transport block: SIB19 rides in an DL-SCH TB scheduled by a DCI inside a SI window, and the DCI, the window timing and the cell SIB1 are outside what this module builds\n'
    rm -rf "$work"
    return 0
}

ntn_sib19_carrier_usage() {
    cat >&2 <<'EOF'
USAGE	--sib19-carrier [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN] [--ref-hex HEX] [--dist M] [--period rfN] [--window SLOTS]
EOF
    return 2
}


ntn_sib19_build() {
    local koffset=15 epoch_sfn=0 epoch_sub=0 validity=s20 kmac=1 ref_hex="" dist=""
    while (( $# )); do
        case "$1" in
            --koffset)   koffset="${2:-}";  shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --epoch-sfn) epoch_sfn="${2:-}"; shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --epoch-sub) epoch_sub="${2:-}"; shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --validity)  validity="${2:-}";  shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --kmac)      kmac="${2:-}";      shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --ref-hex)   ref_hex="${2:-}";   shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            --dist)      dist="${2:-}";      shift 2 || { ntn_sib19_build_usage; return 2; } ;;
            *)           ntn_sib19_build_usage; return 2 ;;
        esac
    done
    [[ "$koffset" =~ ^[0-9]+$ && "$koffset" -ge 1 && "$koffset" -le 1023 ]] || {
        printf 'ERROR\t--koffset wants 1..1023 (TS 38.331 NTN-Config)\n' >&2; return 2; }
    [[ "$epoch_sfn" =~ ^[0-9]+$ && "$epoch_sfn" -le 1023 ]] || {
        printf 'ERROR\t--epoch-sfn wants 0..1023\n' >&2; return 2; }
    [[ "$epoch_sub" =~ ^[0-9]+$ ]] || { printf 'ERROR\t--epoch-sub wants whole slots\n' >&2; return 2; }
    [[ "$kmac" =~ ^[0-9]+$ && "$kmac" -ge 1 && "$kmac" -le 512 ]] || {
        printf 'ERROR\t--kmac wants 1..512\n' >&2; return 2; }
    if [[ -n "$ref_hex" && ! "$ref_hex" =~ ^[0-9A-Fa-f]+$ ]]; then
        printf 'ERROR\t--ref-hex wants hex digits\n' >&2; return 2
    fi
    if [[ -n "$dist" && ! "$dist" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\t--dist wants whole metres\n' >&2; return 2
    fi
    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tSIB19 cannot be built: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tThe encoder is tools/nr_rrc.py over the generated table; regenerate and re-certify it as the decode path says\n' >&2
        return 2
    fi
    local work; work=$(mktemp -d)
    local json="$work/sib19.json"
    {
        printf '{"ntn-Config-r17":{"epochTime-r17":{"sfn-r17":%s,"subFrameNR-r17":%s},' "$epoch_sfn" "$epoch_sub"
        printf '"ntn-UlSyncValidityDuration-r17":"%s","cellSpecificKoffset-r17":%s,"kmac-r17":%s}' "$validity" "$koffset" "$kmac"
        if [[ -n "$ref_hex" ]]; then printf ',"referenceLocation-r17":{"$hex":"%s"}' "$ref_hex"; fi
        if [[ -n "$dist" ]]; then printf ',"distanceThresh-r17":%s' "$dist"; fi
        printf '}'
    } > "$json"
    local out rc=0
    out=$(python3 "$root/tools/nr_rrc.py" encode SIB19_r17 "$json" 2>&1) || rc=$?
    rm -rf "$work"
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return "$rc"
    fi
    printf 'role\tSIB19_r17\n'
    printf '%s\n' "$out" | grep -v '^family'
    printf 'koffset\t%s\n' "$koffset"
    printf 'epoch_sfn\t%s\n' "$epoch_sfn"
    printf 'epoch_subframe\t%s\n' "$epoch_sub"
    printf 'validity\t%s\n' "$validity"
    [[ -n "$ref_hex" ]] && printf 'reference_location\t0x%s\n' "$(printf '%s' "$ref_hex" | tr 'a-f' 'A-F')"
    [[ -n "$dist" ]] && printf 'distance_thresh_m\t%s\n' "$dist"
    printf 'note\tthis is the information element a cell broadcasts; nothing here transmits it, and a receiver only acts on it if the cell it came from passed the checks it cannot forge\n'
    printf 'ref\t3GPP TS 38.331 SIB19-r17 / NTN-Config-r17\n'
    return 0
}

ntn_sib19_build_usage() {
    cat >&2 <<'EOF'
USAGE	--sib19-build [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN] [--kmac N] [--ref-hex HEX] [--dist M]
WHY	builds the SIB19-r17 information element and encodes it through the same unaligned-PER table the --sib19 decoder reads
EOF
}

ntn_sib19() {
    local hex="${1:-}"
    local root="${IMSISTING_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -r "$root/tools/nr_rrc.py" || ! -r "$root/tools/nr_rrc_layout.py" ]]; then
        printf 'ERROR\tSIB19 cannot be decoded: tools/nr_rrc_layout.py is missing\n' >&2
        printf 'WHY\tThe decoder is tools/nr_rrc.py over the generated table tools/nr_rrc_layout.py. Regenerate it with tools/asn1gen.py --family nr and re-certify it with tools/lte-per-oracle/verify_per.py --table tools/nr_rrc_layout.py; a decoder without its table prints fields it invented.\n' >&2
        return 2
    fi
    if [[ -z "$hex" ]]; then
        printf 'ERROR\tsib19 needs a message as hex\n' >&2
        printf 'WHY\tSIB19 is a TS 38.331 IE carried on BCCH-DL-SCH, and this module reads it from bits you supply: the message is decoded, the transport block it arrived in is not.\n' >&2
        printf 'USAGE\t--sib19 <hex>\n' >&2
        return 2
    fi
    python3 "$root/tools/nr_rrc.py" decode SIB19_r17 "$hex" || return 1
}

# ── feeder link: not computed ───────────────────────────────────────────
# SIB19 carries no feeder gateway position, so the gateway-satellite geometry
# is not derivable from anything this module reads. What the old table called
# "exposure" was a topology sketch, not a measurement or a computed quantity.
ntn_feeder_link() {
    printf 'band\tuplink_ghz\tdownlink_ghz\tallocation\n'
    printf 'Ka\t27.5-31.0\t17.3-20.2\tFSS feeder\n'
    printf 'Ku\t13.75-14.5\t10.7-12.75\tFSS feeder\n'
    printf 'V\t47.2-50.2\t37.5-42.5\tFSS feeder\n'
    printf 'Q\t47.2-48.2\t42.5-43.5\tFSS feeder\n'
    printf 'payload\ttransparent\tthe payload translates the feeder carrier to the service band and back; it does not demodulate, so nothing in the relay checks what it carries\n'
    printf 'payload\tregenerative\tthe gNB is on board; the feeder carries backhaul, IP or GTP-U, and is a network transport rather than a relay\n'
    printf 'signalled\tSIB19\tservice link only: satellite state vector, TA, K_offset, reference location, distanceThresh\n'
    printf 'not-signalled\tgateway\tthe earth-station position is in a filing, never in the broadcast\n'
    printf 'gateway-source\tITU space network filing, earth-station licence, operator frequency plan\n'
    printf 'geometry\t--feeder-look <gw-lat> <gw-lon> <tle> [minutes] [MHz]\n'
    printf 'budget\t--feeder-budget <freq-mhz> <range-km> <eirp-dbw> [bw-khz] [g-over-t] [sfd-dbw-m2]\n'
    printf 'capture\t--feeder-capture <tle> <tsince> <atk-lat> <atk-lon> [--gw-lat D --gw-lon D] [--gw-eirp-dbw D] [--target-js-db D] [--freq-mhz D] [--dish-m D]\n'
    return 0
}

# ── feeder geometry from the gateway's side ─────────────────────────────
# The gateway is the other end of the same satellite the service link sees, so
# the geometry is ntn_look from a different ground point: range, elevation,
# azimuth, range-rate, Doppler and free-space loss, sampled across the pass.
# Everything else about a feeder is a link budget, which is the next verb.
ntn_feeder_look() {
    local lat="${1:-}" lon="${2:-}" file="${3:-}" minutes="${4:-15}" freq="${5:-30}"
    [[ -n "$lat" && -n "$lon" && -r "$file" ]] || {
        printf 'ERROR\t--feeder-look needs <gateway-lat> <gateway-lon> <tle-file> [minutes] [MHz]\n' >&2; return 2; }
    local epoch_ts epoch_iso epoch_jd
    epoch_ts=$(ntn_epoch_ts "$file") || {
        printf 'GUARD\tepoch-unreadable\trefusing: the element set has no epoch, so samples cannot be placed on a clock\n'
        return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")

    printf 'field\tvalue\n'
    printf 'gateway_lat\t%s\n' "$lat"
    printf 'gateway_lon\t%s\n' "$lon"
    printf 'feeder_mhz\t%s\n' "$freq"
    printf 'epoch_utc\t%s\n' "$epoch_iso"
    printf 'tsince_min\trange_km\telev_deg\taz_deg\trange_rate_kms\tdoppler_hz\tdelay_us\tfspl_db\n'

    local i n step=0.5
    n=$(awk -v m="$minutes" 'BEGIN{printf "%d", m*2}')
    local first="" last="" maxel=-90 seen=0
    for (( i = 0; i <= n; i++ )); do
        local tsince rv
        tsince=$(awk -v i="$i" -v s="$step" 'BEGIN{printf "%.2f", i*s}')
        rv=$(ntn_state_at "$file" "$tsince") || break
        [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; break; }
        local rx ry rz vx vy vz
        rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
        vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)
        local gmst look
        gmst=$(ntn_topocentric "$lat" "$lon" 0 "$tsince" "$epoch_jd")
        look=$(ntn_look "$lat" "$lon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$gmst")
        local rng el az rrate
        rng=$(printf '%s' "$look" | cut -f1); el=$(printf '%s' "$look" | cut -f2)
        az=$(printf '%s' "$look" | cut -f3); rrate=$(printf '%s' "$look" | cut -f4)
        awk -v t="$tsince" -v r="$rng" -v el="$el" -v az="$az" -v rr="$rrate" \
            -v f="$freq" -v c="$NTN_C_KM_S" 'BEGIN{
            if (el < 0) exit 0
            dop = -1 * (f*1e6) * rr / c
            dly = r / c * 1e6
            fspl = 92.45 + 20*log(r)/log(10) + 20*log(f)/log(10)
            printf "%s\t%.3f\t%.3f\t%.1f\t%.4f\t%.1f\t%.1f\t%.2f\n", t, r, el, az, rr, dop, dly, fspl
        }'
        if awk -v e="$el" 'BEGIN{exit !(e >= 0)}'; then
            seen=$(( seen + 1 ))
            [[ -z "$first" ]] && first="$tsince"
            last="$tsince"
            maxel=$(awk -v a="$maxel" -v b="$el" 'BEGIN{print (b>a)?b:a}')
        fi
    done
    printf 'visible_samples\t%d\n' "$seen"
    printf 'aos_min\t%s\n' "${first:-unobserved}"
    printf 'los_min\t%s\n' "${last:-unobserved}"
    if (( seen == 0 )); then
        printf 'max_elev_deg\tunobserved\n'
    else
        printf 'max_elev_deg\t%.3f\n' "$maxel"
    fi
    return 0
}

# A feeder link budget, in the two numbers that decide whether the transponder
# is yours: how much flux density the carrier puts on the satellite compared
# with the transponder's saturation flux density, and the carrier-to-noise the
# same carrier produces. A bent-pipe transponder has one output and an AGC, so
# a carrier strong enough to compress it takes the output regardless of who is
# licensed to be there.
ntn_feeder_budget() {
    local freq="${1:-30}" rng="${2:-35786}" eirp="${3:-70}"
    local bw="${4:-36}" gt="${5:-0}" sfd="${6:--90}"
    local num='^[0-9]+([.][0-9]+)?$' neg='^-?[0-9]+([.][0-9]+)?$'
    for v in "$freq" "$rng" "$bw"; do
        [[ "$v" =~ $num ]] || { printf 'ERROR\tfrequency, range and bandwidth must be positive numbers\n' >&2; return 2; }
    done
    [[ "$eirp" =~ $neg && "$gt" =~ $neg && "$sfd" =~ $neg ]] || {
        printf 'ERROR\teirp, G/T and SFD must be numbers\n' >&2; return 2; }

    awk -v F="$freq" -v R="$rng" -v E="$eirp" -v B="$bw" -v GT="$gt" -v SFD="$sfd" 'BEGIN{
        if (F <= 0 || R <= 0 || B <= 0) { print "ERROR\tfrequency, range and bandwidth must be positive"; exit 2 }
        pi = atan2(0,-1)
        fspl = 92.45 + 20*log(R)/log(10) + 20*log(F)/log(10)
        dm = R*1000
        spread = 10*log(4*pi*dm*dm)/log(10)
        prx = E - fspl
        flux = E - spread
        sat = SFD - flux
        cn0 = E - fspl + GT + 228.6
        cn = cn0 - 10*log(B*1e6)/log(10)
        printf "field\tvalue\n"
        printf "feeder_mhz\t%.3f\n", F
        printf "range_km\t%.3f\n", R
        printf "eirp_dbw\t%.2f\n", E
        printf "eirp_source\tsupplied\n"
        printf "bandwidth_khz\t%.3f\n", B
        printf "g_over_t_db_per_k\t%.2f\n", GT
        printf "g_over_t_source\t%s\n", (GT == 0 ? "assumed: 0 dB/K" : "supplied")
        printf "sfd_dbw_m2\t%.2f\n", SFD
        printf "sfd_source\t%s\n", (SFD == -90 ? "assumed: -90 dBW/m2, a typical bent-pipe saturation flux" : "supplied")
        printf "path_loss_db\t%.2f\n", fspl
        printf "spreading_loss_db\t%.2f\n", spread
        printf "received_dbw\t%.2f\n", prx
        printf "flux_density_dbw_m2\t%.2f\n", flux
        printf "saturation_margin_db\t%.2f\n", sat
        printf "cn0_db_hz\t%.2f\n", cn0
        printf "cn_db\t%.2f\n", cn
        verdict = (sat < 0) ? "saturated" : (cn <= 0 ? "below-noise" : "nominal")
        printf "verdict\t%s\n", verdict
        printf "not_modelled\train fade, antenna sidelobes, uplink power control, transponder AGC time constant, polarization isolation\n"
    }'
}

# Capture margin: the interferer's carrier arrives at the same transponder as
# the gateway's, so the question is a ratio of two flux densities, i.e. of two
# EIRPs and two slant ranges. Only the ranges are measurable from the element
# set; the gateway's own EIRP is an operating parameter, so it is an argument
# and is reported with its source. Everything the geometry cannot supply is
# reported as not-supplied rather than filled in.
ntn_feeder_capture() {
    local file="${1:-}" tsince="${2:-0}" alat="${3:-}" alon="${4:-}"
    local gwlat="" gwlon="" gweirp="70" js="0" freq="30" dish="" win="15" eff="0.65"
    local gweirp_src="assumed" js_src="assumed"
    shift 4 2>/dev/null || shift $#
    while (( $# > 0 )); do
        case "$1" in
            --gw-lat)   gwlat="${2:-}"; shift 2 ;;
            --gw-lon)   gwlon="${2:-}"; shift 2 ;;
            --gw-eirp-dbw) gweirp="${2:-70}"; gweirp_src="supplied"; shift 2 ;;
            --target-js-db) js="${2:-0}"; js_src="supplied"; shift 2 ;;
            --freq-mhz) freq="${2:-30}"; shift 2 ;;
            --dish-m)   dish="${2:-}"; shift 2 ;;
            --eff)      eff="${2:-0.65}"; shift 2 ;;
            --window-min) win="${2:-15}"; shift 2 ;;
            *) printf 'ERROR\tunknown argument: %s\n' "$(ntn_sanitize "$1")" >&2
               printf 'WHY\tusage: --feeder-capture <tle> <tsince> <atk-lat> <atk-lon> [--gw-lat D --gw-lon D] [--gw-eirp-dbw D] [--target-js-db D] [--freq-mhz D] [--dish-m D] [--eff D] [--window-min N]\n' >&2
               return 2 ;;
        esac
    done
    [[ -r "$file" ]] || { printf 'ERROR\t--feeder-capture needs a readable element set\n' >&2; return 2; }
    local num='^-?[0-9]+([.][0-9]+)?$'
    [[ "$alat" =~ $num && "$alon" =~ $num ]] || {
        printf 'ERROR\tattacker latitude and longitude must be numbers\n' >&2; return 2; }
    if [[ -n "$gwlat" || -n "$gwlon" ]]; then
        [[ "$gwlat" =~ $num && "$gwlon" =~ $num ]] || {
            printf 'ERROR\tgateway latitude and longitude must both be numbers\n' >&2; return 2; }
    fi

    local epoch_ts epoch_iso epoch_jd
    epoch_ts=$(ntn_epoch_ts "$file") || {
        printf 'GUARD\tepoch-unreadable\trefusing: no clock for the samples\n'; return 1; }
    epoch_iso=$(date -u -d "@$epoch_ts" +%Y-%m-%dT%H:%M:%SZ)
    epoch_jd=$(ntn_jd "$epoch_iso")

    local rv; rv=$(ntn_state_at "$file" "$tsince") || {
        printf 'GUARD\tstate-unavailable\trefusing: the element set would not propagate to %s min\n' "$tsince"; return 1; }
    [[ "$rv" == GUARD* ]] && { printf '%s\n' "$rv"; return 1; }
    local rx ry rz vx vy vz
    rx=$(printf '%s' "$rv" | sed -n 1p | cut -f1); ry=$(printf '%s' "$rv" | sed -n 1p | cut -f2); rz=$(printf '%s' "$rv" | sed -n 1p | cut -f3)
    vx=$(printf '%s' "$rv" | sed -n 2p | cut -f1); vy=$(printf '%s' "$rv" | sed -n 2p | cut -f2); vz=$(printf '%s' "$rv" | sed -n 2p | cut -f3)

    local agmst alook arng ael arate
    agmst=$(ntn_topocentric "$alat" "$alon" 0 "$tsince" "$epoch_jd")
    alook=$(ntn_look "$alat" "$alon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$agmst")
    arng=$(printf '%s' "$alook" | cut -f1); ael=$(printf '%s' "$alook" | cut -f2); arate=$(printf '%s' "$alook" | cut -f4)

    local gwrng="" gwel=""
    if [[ -n "$gwlat" ]]; then
        local ggmst glook
        ggmst=$(ntn_topocentric "$gwlat" "$gwlon" 0 "$tsince" "$epoch_jd")
        glook=$(ntn_look "$gwlat" "$gwlon" 0 "$rx" "$ry" "$rz" "$vx" "$vy" "$vz" "$ggmst")
        gwrng=$(printf '%s' "$glook" | cut -f1); gwel=$(printf '%s' "$glook" | cut -f2)
    fi

    # Window: a capture only exists while the interferer can see the satellite.
    local i seen=0 maxel=-90 step=0.5
    local n; n=$(awk -v m="$win" 'BEGIN{printf "%d", m*2}')
    for (( i = 0; i <= n; i++ )); do
        local ts rv2
        ts=$(awk -v i="$i" -v s="$step" 'BEGIN{printf "%.2f", i*s}')
        rv2=$(ntn_state_at "$file" "$ts") || break
        [[ "$rv2" == GUARD* ]] && break
        local wx wy wz wvx wvy wvz
        wx=$(printf '%s' "$rv2" | sed -n 1p | cut -f1); wy=$(printf '%s' "$rv2" | sed -n 1p | cut -f2); wz=$(printf '%s' "$rv2" | sed -n 1p | cut -f3)
        wvx=$(printf '%s' "$rv2" | sed -n 2p | cut -f1); wvy=$(printf '%s' "$rv2" | sed -n 2p | cut -f2); wvz=$(printf '%s' "$rv2" | sed -n 2p | cut -f3)
        local wgmst wlook wel
        wgmst=$(ntn_topocentric "$alat" "$alon" 0 "$ts" "$epoch_jd")
        wlook=$(ntn_look "$alat" "$alon" 0 "$wx" "$wy" "$wz" "$wvx" "$wvy" "$wvz" "$wgmst")
        wel=$(printf '%s' "$wlook" | cut -f2)
        if awk -v e="$wel" 'BEGIN{exit !(e >= 5)}'; then
            seen=$(( seen + 1 ))
            maxel=$(awk -v a="$maxel" -v b="$wel" 'BEGIN{print (b>a)?b:a}')
        fi
        unset wx wy wz wvx wvy wvz wgmst wlook wel
    done

    awk -v T="$tsince" -v X="$rx" -v Y="$ry" -v Z="$rz" \
        -v AL="$alat" -v AO="$alon" -v AR="$arng" -v AE="$ael" -v ARR="$arate" \
        -v GR="$gwrng" -v GE="$gwel" -v GI="$gweirp" -v GIS="$gweirp_src" \
        -v JS="$js" -v JSS="$js_src" -v F="$freq" -v D="$dish" -v EFF="$eff" \
        -v VIS="$seen" -v MXE="$maxel" -v C="299792.458" -v WIN="$win" 'BEGIN{
        pi = atan2(0,-1)
        d2 = log(10)
        printf "field\tvalue\n"
        printf "tsince_min\t%s\n", T
        printf "sat_x_km\t%.6f\n", X
        printf "sat_y_km\t%.6f\n", Y
        printf "sat_z_km\t%.6f\n", Z
        printf "attacker_lat\t%s\n", AL
        printf "attacker_lon\t%s\n", AO
        printf "attacker_range_km\t%.3f\n", AR
        printf "attacker_elev_deg\t%.3f\n", AE
        printf "attacker_range_rate_kms\t%.4f\n", ARR
        printf "attacker_spreading_db\t%.2f\n", 10*log(4*pi*(AR*1000)*(AR*1000))/d2
        printf "attacker_fspl_db\t%.2f\n", 92.45 + 20*log(AR)/d2 + 20*log(F)/d2
        printf "attacker_doppler_hz\t%.1f\n", -1*(F*1e6)*(ARR*1000)/(C*1000)
        printf "gateway_source\t%s\n", (GR == "" ? "not-supplied" : "supplied")
        printf "gateway_eirp_dbw\t%.2f\n", GI
        printf "gateway_eirp_source\t%s\n", GIS
        printf "target_js_db\t%.2f\n", JS
        printf "target_js_source\t%s\n", JSS
        if (GR != "") {
            printf "gateway_range_km\t%.3f\n", GR
            printf "gateway_elev_deg\t%.3f\n", GE
            printf "gateway_spreading_db\t%.2f\n", 10*log(4*pi*(GR*1000)*(GR*1000))/d2
            adv = 10*log(4*pi*(AR*1000)*(AR*1000))/d2 - 10*log(4*pi*(GR*1000)*(GR*1000))/d2
            req = GI + adv + JS
            printf "geometry_advantage_db\t%.2f\n", adv
            printf "required_eirp_dbw\t%.2f\n", req
            if (D != "") {
                g = 10*log(EFF*(pi*D*(F*1e9)/299792458)*(pi*D*(F*1e9)/299792458))/d2
                printf "dish_m\t%.3f\n", D
                printf "dish_efficiency\t%.2f\n", EFF
                printf "dish_gain_dbi\t%.2f\n", g
                printf "required_tx_w\t%.3f\n", 10^((req-g)/10)
            }
        } else {
            printf "geometry_advantage_db\tunobserved\n"
            printf "required_eirp_dbw\tunobserved\n"
            printf "gateway_missing\tthe interferer-to-gateway ratio needs the gateway position; supply --gw-lat and --gw-lon from a filing\n"
        }
        printf "window_minutes\t%s\n", WIN
        printf "visible_minutes\t%.1f\n", VIS*0.5
        if (VIS == 0) printf "max_elev_deg\tunobserved\n"
        else printf "max_elev_deg\t%.3f\n", MXE
        verdict = "favourable"
        if (VIS == 0) verdict = "no-pass"
        else if (AE < 5) verdict = "hostile-geometry"
        else if (GR == "") verdict = "gateway-unknown"
        else if (adv >= 0) verdict = "uphill"
        else if (adv > -10) verdict = "marginal"
        printf "verdict\t%s\n", verdict
        printf "not_modelled\train fade, transmit sidelobes and adjacent-satellite isolation, uplink power control, transponder AGC time constant, polarization\n"
    }'
}

# ── F4: listening for a satellite cell ──────────────────────────────────
# A satellite cell is an ordinary NR cell with a round trip that no terrestrial
# timing budget assumed, so the receiver half is a tuning problem plus a
# signature: a cell that broadcasts SIB19, whose timing moves with the sky, and
# whose round trip is milliseconds rather than microseconds.
# ── F6: reselection between a terrestrial cell and a satellite one ──────
# A UE picks between the two cells the same way it picks between any two:
# the S criterion, the cell-ranking criterion and the reselection timers. NTN
# adds a distance gate (the UE must be inside the cell's distanceThresh of its
# reference location, TS 38.304 5.2.4.6) and a validity timer that expires the
# SIB19 information. This works out which way the UE goes, and what has to move
# to make it go the other way.
ntn_reselect() {
    local ter="" sat="" dist="" hyst="" validity="" barring="" t_resel="" qrxlevmin=""
    while (( $# )); do
        case "$1" in
            --terrestrial-rsrp) ter="${2:-}";    shift 2 || { ntn_resel_usage; return 2; } ;;
            --satellite-rsrp)   sat="${2:-}";    shift 2 || { ntn_resel_usage; return 2; } ;;
            --distance-km)      dist="${2:-}";   shift 2 || { ntn_resel_usage; return 2; } ;;
            --hysteresis-db)    hyst="${2:-}";   shift 2 || { ntn_resel_usage; return 2; } ;;
            --validity-s)       validity="${2:-}"; shift 2 || { ntn_resel_usage; return 2; } ;;
            --barred)           barring=1;        shift ;;
            --q-rxlevmin)       qrxlevmin="${2:-}"; shift 2 || { ntn_resel_usage; return 2; } ;;
            *)                  ntn_resel_usage; return 2 ;;
        esac
    done
    if [[ -z "$ter" || -z "$sat" ]]; then ntn_resel_usage; return 2; fi
    for v in "$ter" "$sat" "$dist" "$hyst" "$validity" "$qrxlevmin"; do
        if [[ -n "$v" && ! "$v" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
            printf 'ERROR\t%s wants a number\n' "$v" >&2; return 2
        fi
    done
    awk -v ter="$ter" -v sat="$sat" -v dist="$dist" -v hyst="${hyst:-2}" \
        -v validity="$validity" -v barred="$barring" -v qmin="${qrxlevmin:--140}" 'BEGIN{
        printf "input\tterrestrial_rsrp\t%s\n", ter
        printf "input\tsatellite_rsrp\t%s\n", sat
        if (dist != "") printf "input\tdistance_km\t%s\n", dist
        # the S criterion in its simplest usable form: the measured RSRP has to
        # clear Qrxlevmin by the power offsets, and the hysteresis keeps a cell
        # that is only marginally better from being reselected onto
        printf "criterion\tS_terrestrial\t%s\n", (ter + 0 >= qmin + 0) ? "pass" : "fail"
        printf "criterion\tS_satellite\t%s\n", (sat + 0 >= qmin + 0) ? "pass" : "fail"
        gap = (sat + 0) - (ter + 0)
        printf "margin_db\t%.1f\n", gap
        if (barred == 1) printf "criterion\tterrestrial_barred\tbarred\n"
        if (dist != "" && dist + 0 > 0) {
            printf "gate\tdistance_thresh\tnot supplied, so the distance gate is assumed to pass\n"
        }
        if (validity != "") {
            printf "gate\tvalidity_s\t%s\n", validity
            printf "gate\tvalidity_expiry\tno expiry while the SIB19 repeats inside the window\n"
        }
        verdict = "stays_terrestrial"
        if (barred == 1) verdict = "reselection_to_satellite_when_S_passes"
        else if (gap > hyst + 0) verdict = "reselection_to_satellite"
        else if (gap < -1 * (hyst + 0)) verdict = "stays_terrestrial"
        else verdict = "marginal_inside_hysteresis"
        printf "verdict\t%s\n", verdict
        if (verdict == "reselection_to_satellite") {
            printf "finding\tranking_decides\tINFO\tthe satellite cell ranks above the terrestrial one by %.1f dB, more than the %.1f dB of hysteresis, so the reselection is the UE doing what it was told\n", gap, hyst
        }
        printf "finding\tthree_levers\tMEDIUM\twhat moves the UE toward satellite is the barring, the Qrxlevmin or the measured power of the terrestrial cell: a fake SIB1 that bars it, a lowered RSRP from its direction, or a policy that prefers NTN\n"
        printf "finding\toperator_selectable\tINFO\tNTN preference is also a UE policy and a network decision, so a diversion can be requested rather than forced\n"
        printf "ref\t3GPP TS 38.304 5.2.4 (cell selection and reselection), TS 38.331 SIB19 distanceThresh and t-Service\n"
        printf "limit\tthis compares RSRP and the hysteresis; the real criteria also weigh Srxlev offsets, the NTN distance gate and the validity timer, which need fields this module is not given\n"
    }'
}

ntn_resel_usage() {
    cat >&2 <<'EOF'
USAGE	--ntn-reselect --terrestrial-rsrp DBM --satellite-rsrp DBM [--distance-km KM] [--hysteresis-db DB] [--validity-s S] [--barred] [--q-rxlevmin DBM]
WHY	works out which cell the UE reselects to, and which lever moves it the other way
EOF
}

ntn_scan_plan() {
    cat <<'EOF'
status	plan
what	listen for an NTN cell's downlink and tell it apart from a terrestrial one
hardware	an SDR that covers the band (n255 DL 1525-1559 MHz, n256 DL 2170-2200 MHz) with a pass to receive, or an NTN-capable UE with the satellite profile enabled
software	a receiver that decodes NR downlink: srsRAN Project with an NR-NTN build, or a spectrum recorder plus an offline decoder; the SIB19 this module decodes (--sib19) is the payload to look for
step	tune	the band in the table above; a satellite downlink is a normal NR carrier with a wide beam, so a 20 MHz capture at the right centre frequency is enough to find it
step	find	the SSB and read the cell's MIB; a satellite cell's MIB is unremarkable, so the discriminator is what comes after it
step	decode	read SIB1, then SIB19 if the cell broadcasts it; SIB19 is what makes the cell NTN and this module's --sib19 reads it once you have the bits
step	measure	the round trip: a terrestrial cell is under about 0.15 ms, an NTN cell is 2-40 ms one way, so the timing advance the network commands is the first give-away
step	watch	the timing advance and Doppler over a pass: a satellite's Doppler sweeps through zero as it passes overhead, which no terrestrial cell does
step	confirm	the ephemeris in SIB19 against a published orbit: a cell claiming a satellite that is not overhead is a fake, and that is the F5 question
signal	ta_extended	a timing advance beyond the LTE range (1282 units) or a K_offset above 1 ms is an NTN-sized delay
signal	sib19	the cell broadcasts SIB19, which a terrestrial cell has no reason to send
signal	doppler_sweep	a carrier frequency offset that changes sign over minutes, consistent with a pass
signal	rtt_jitter	a round trip that drifts smoothly rather than sitting at a constant value
finding	ntn_signals_are_three	INFO	no single field says NTN: the round trip, the SIB19 presence and the Doppler sweep together do, and a cell that fakes one usually misses the others
verdict	receive_plan_only
limit	the capture and the decode happen outside this module; it gives the tuning, the signature and the interpretation, not a receiver
note	receiving a satellite downlink in a band you are authorised to receive is passive; decoding an operator's signalling beyond what a normal UE does is covered by the local rules on radio interception
EOF
}

# ── F5: broadcasting a fake satellite cell ──────────────────────────────
# The transmit half is harder than the terrestrial fake cell for three reasons:
# the band, the delay, and the orbit the UE can check.
ntn_fakecell_plan() {
    cat <<'EOF'
status	plan
what	broadcast downlink that presents itself as an NTN cell
hardware	an SDR with a PA on the NTN downlink band (n255 DL 1525-1559 MHz or n256 DL 2170-2200 MHz); transmitting there is licensed to the operator
software	an NR gNB that can be told its own delay profile (srsRAN Project with NTN support), and this module's --sib19-build for the SIB19 the cell must broadcast
need_band	a carrier in the NTN band: a UE only scans bands its profile lists, so the fake cell is invisible to a phone that is not NTN-enabled
need_sib19	SIB19 with a plausible ephemeris, a K_offset sized for the delay, and a reference location; without SIB19 the cell is not NTN to the UE
need_delay	the gNB must run with the propagation delay it claims: a fake NTN cell that answers at terrestrial speed is rejected by timing checks, and this module's --ephemeris-hijack works out how far a wrong number puts the UE
need_uplink	if the session goes beyond broadcast and the UE tries to attach, the uplink has to be received and relayed, which is the duplex the terrestrial fake cell only needs once
step	build	--sib19-build --koffset N --validity sN with a reference location and distance threshold that match the claimed orbit
step	run	bring up the gNB with the delay profile, then let the UE find the cell; watch the timing advance the UE reports back, which should sit where the delay predicts
step	observe	what a UE does with a fake NTN cell is the interesting part: it holds the timing for the validity window and then declares out of sync
finding	three_locks	HIGH	band, SIB19 and delay are three independent locks and a real NTN pass opens all three at once
finding	orbit_checkable	MEDIUM	the ephemeris is checkable against public orbit data and against GNSS, so the fake cell needs a satellite that is genuinely overhead or a UE that does not check
finding	uplink_needed_late	INFO	broadcast needs only the downlink; anything past that needs the duplex the terrestrial fake cell also needs
verdict	transmit_plan_only
limit	the transmitter and the delay-capable gNB are outside this module; --sib19-build gives the payload and --ephemeris-hijack gives the consequence of the numbers
note	transmitting on an NTN band is licensed to that operator; a fake cell on those frequencies is both a radio offence and an interference problem
EOF
}

ntn_plan() {
    cat <<'EOF'
status	handoff
what	operating or observing an NTN cell
hardware	an NTN-capable UE, or an SDR with a satellite pass to receive (a LEO beacon on the feeder/service downlink)
software	computed here: --doppler, --range, --ta and --koffset; SIB19 is decoded and built through the generated NR table (--sib19, --sib19-build); refused here: --feeder (no gateway geometry)
flow	1. --doppler and --range for the pass geometry  2. --ta and --koffset for the timing budget  3. --sib19-build to forge what a satellite cell would broadcast, --sib19 to read one back
note	transmitting into a satellite link needs that operator's authorisation; this module computes on geometry you supply
EOF
}

# ── behind the satellite: the feeder carrier ────────────────────────────
# A bent-pipe satellite repeats whatever the gateway sends it, so everything
# the operator puts between its own sites crosses the sky in one carrier and
# comes down over a whole footprint. That is a receive-only surface: no radio
# is keyed here, and no carrier is demodulated here either (there is no DVB-S2
# demodulator or FEC decoder in this tree). What this verb answers is what sits
# between the transponder and the traffic, and where an operator can put
# encryption on the way.
ntn_backhaul() {
    case "${1:-chain}" in
      all) ntn_backhaul chain; ntn_backhaul crypto; ntn_backhaul kit; return 0 ;;
      chain)
        printf 'question\twhat sits between the transponder and the operator traffic\n'
        printf 'carrier\t%s\t%s\n' 'DVB-S2 / DVB-S2X' 'ETSI EN 302 307-1 and -2; also DVB-S on older links'
        printf 'direction\t%s\t%s\n' 'downlink' 'the return path is a different carrier and is not on this one'
        printf 'chain\t%s\t%s\t%s\t%s\n' 1 'dvb-s2' 'QPSK/8PSK/16APSK/32APSK and LDPC/BCH forward error correction' 'demodulated by the receiver, not here'
        printf 'chain\t%s\t%s\t%s\t%s\n' 2 'bb-frame' 'baseband frame with stream adaptation and a CRC-8 header' 'the unit an FEC block carries'
        printf 'chain\t%s\t%s\t%s\t%s\n' 3 'mpeg-ts' '188-octet transport stream, sync byte 0x47, demultiplexed by PID' 'one PID is one logical channel'
        printf 'chain\t%s\t%s\t%s\t%s\n' 4 'gse-or-mpe' 'GSE (TS 102 606) or MPE/MPE2 wrap the IP packets' 'GSE header is 4 octets plus a length field'
        printf 'chain\t%s\t%s\t%s\t%s\n' 5 'ip' 'IPv4 or IPv6 bearing TCP, UDP or ESP' 'the first layer whose content is checkable'
        printf 'chain\t%s\t%s\t%s\t%s\n' 6 'application' 'SIP and RTP, DNP3, SNMP, XML, TLS' 'what a cleared carrier reads as'
        printf 'demodulate\t%s\t%s\n' 'no' 'refused here: no DVB-S2 demodulator and no FEC decoder in this tree'
        printf 'needs\t%s\t%s\n' 'a tuner and a demodulator' 'or the published parser (ucsdsysnet/dontlookup) before any byte below means anything'
        printf 'ref\t%s\t%s\n' 'ETSI EN 302 307-1' 'DVB-S2 framing and FEC'
        printf 'ref\t%s\t%s\n' 'TS 102 606' 'GSE encapsulation'
        printf 'limit\t%s\t%s\n' 'standards only' 'no carrier is captured, tuned or demodulated by this verb'
        printf 'verdict\t%s\n' 'feeder_chain_described'
        return 0 ;;
      crypto)
        printf 'question\twhere encryption can sit between the transponder and the traffic\n'
        printf 'layer\t%s\t%s\t%s\n' 'link' '10 percent of transponders scrambled' 'subscription television, almost all of it; the scrambling standard is published and the keys are not'
        printf 'layer\t%s\t%s\t%s\n' 'network' '6 percent of transponders carrying IPsec' 'the operator own tunnel; whether it encrypts is a configuration choice, not a default'
        printf 'layer\t%s\t%s\t%s\n' 'application' 'TLS on end-user traffic' 'the one layer that is usually right, because a browser or a phone insisted'
        printf 'measured\t%s\t%s\n' '411 transponders across 39 satellites' 'one site, 2024-2025, Ku band, downlink only'
        printf 'operator\t%s\t%s\t%s\t%s\n' 't-mobile' '4G backhaul' 'call audio and SMS contents, through an IPsec tunnel configured with a null cipher' 'encrypted after disclosure'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'at-t-mexico' '4G backhaul' 'security keys and subscriber identities, no audio and no text' 'transponders no longer active'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'telmex' 'voice' 'unencrypted SIP signalling and RTP media' 'still broadcasting at publication'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'mexican-navy' 'asset tracking' 'position updates from tracked units' 'described in the paper'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'inmarsat-government' 'government terminal backhaul' 'IPsec between defence addresses, voice in the clear, terminal configuration files' 'described in the paper'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'pge' 'utility SCADA' 'DNP3 setpoints and SNMPv1 community strings for 267 addresses' 'described in the paper'
        printf 'operator\t%s\t%s\t%s\t%s\n' 'sagenet' 'payment terminals' 'card track data in XML and prepaid balances' 'described in the paper'
        printf 'finding\t%s\t%s\t%s\n' 'tunnel_without_encryption' 'HIGH' 'an IPsec tunnel with a null cipher is a network layer that looks protected and is not'
        printf 'finding\t%s\t%s\t%s\n' 'cleartext_critical_infrastructure' 'HIGH' 'SCADA, payment and voice traffic crossed a broadcast medium with no encryption at any layer'
        printf 'ref\t%s\t%s\n' 'CCS 2025' 'Dai, Heninger, Zhang, Ryan, Levin, Schulman: Dont look up, sensitive internal links in the clear on GEO satellites'
        printf 'limit\t%s\t%s\n' 'published and cited' 'nothing in this tree measured these numbers; they are the paper reported findings, downlink only'
        printf 'verdict\t%s\n' 'encryption_layers_named'
        return 0 ;;
      kit)
        printf 'question\twhat a passive receive station costs\n'
        printf 'kit\t%s\t%s\t%s\n' 'dish' '1.1 m' '180'
        printf 'kit\t%s\t%s\t%s\n' 'motor' '120 degree rotor' '195'
        printf 'kit\t%s\t%s\t%s\n' 'tuner' 'DVB-S2 card' '230'
        printf 'kit\t%s\t%s\t%s\n' 'lnb' 'Ku band' '15'
        printf 'kit\t%s\t%s\t%s\n' 'total' 'under 700 US dollars' '620'
        printf 'kit\t%s\t%s\t%s\n' 'software' 'transponder scanning' '0'
        printf 'band\t%s\t%s\n' 'Ku' '12 to 18 GHz downlink; a television dish is the cheap way onto it'
        printf 'not_needed\t%s\t%s\n' 'a transmitter' 'the surface is receive only'
        printf 'legal\t%s\t%s\n' 'receive only' 'this tree does not descramble subscription television and holds no decoder for it'
        printf 'limit\t%s\t%s\n' 'published figures' 'prices are the paper kit, not a quote'
        printf 'verdict\t%s\n' 'passive_station_costed'
        return 0 ;;
      *)
        printf 'ERROR\tunknown backhaul section: %s\n' "${1:-}" >&2
        printf 'WHY\tthis verb answers chain, crypto or kit\n' >&2
        return 2 ;;
    esac
}

# ── triage: what a cleared carrier reads as ─────────────────────────────
# The input is a text export of an already-parsed capture (tshark -V, strings,
# or the published parser dump). This classifies tokens; it does not parse the
# carrier and it does not claim a protocol from a byte count.
ntn_backhaul_triage() {
    local f="${1:-}"
    [[ -n "$f" ]] || { printf 'ERROR\tno file given\n' >&2; printf 'WHY\tthis verb reads a text export of a parsed feeder capture\n' >&2; return 2; }
    [[ -r "$f" ]] || { printf 'ERROR\tcannot read %s\n' "$f" >&2; printf 'WHY\tthe file must exist and be readable\n' >&2; return 1; }
    local lines found=0
    lines=$(wc -l < "$f" 2>/dev/null || echo 0)
    printf 'input\t%s\n' "$f"
    printf 'lines\t%s\n' "$lines"
    local n t name what sev ref
    while IFS='~' read -r t name what sev ref; do
        [[ -n "$t" ]] || continue
        n=$(grep -Eic -- "$t" "$f" 2>/dev/null || true)
        n=${n:-0}
        if (( n > 0 )); then
            printf 'detection\t%s\t%s\t%s\t%s\t%s\n' "$name" "$n" "$what" "$sev" "$ref"
            found=$(( found + 1 ))
        fi
    done <<'DET'
SIP/2\.0~sip~call signalling, and the numbers in it~HIGH~RFC 3261
INVITE sip~invite~the dialled party in a request line~HIGH~RFC 3261
RTP/~rtp~the audio itself, once the codec is known~HIGH~RFC 3550
DNP3~dnp3~SCADA function codes and setpoints~HIGH~IEEE 1815
community=~snmpv1~an SNMPv1 community string and the device tree behind it~HIGH~RFC 1157
<Track2~track2~payment card track data~HIGH~PCI DSS 4.1
ESP~esp~an IPsec tunnel: present, and not readable~INFO~RFC 4303
TLSv1~tls~a TLS session: present, and not readable~INFO~RFC 8446
DET
   printf 'found\t%s\n' "$found"
    if (( found == 0 )); then
        printf 'verdict\t%s\n' 'nothing_readable_in_this_file'
    else
        printf 'finding\t%s\t%s\t%s\n' 'cleartext_application_traffic' 'HIGH' 'a broadcast carrier carrying application traffic a third party can read'
        printf 'verdict\t%s\n' 'feeder_capture_shows_cleartext'
    fi
    printf 'limit\t%s\t%s\n' 'token classification' 'a match is a token in a text export, not a decoded protocol message'
    return 0
}

# ── legacy satellite cellular: GMR ──────────────────────────────────────
# GMR is the air interface of the satellite phones, not the broadcast feed a
# WAN link rides on. It is a GSM derivative with its own layer 2 and its own
# authentication, so nothing in the NR SIB19 path above applies to it.
ntn_gmr() {
    case "${1:-all}" in
      all|1|2) ;;
      *) printf 'ERROR\tunknown generation: %s\n' "$1" >&2; printf 'WHY\tthis verb answers 1, 2 or all\n' >&2; return 2 ;;
    esac
    local want="${1:-all}"
    printf 'question\twhat a satellite phone air interface is\n'
    if [[ "$want" == "all" || "$want" == "1" ]]; then
        printf 'spec\t%s\t%s\t%s\n' 'gmr-1' 'ETSI TS 101 376' 'GSM derived; variants GmPRS and GMR-1 3G; Thuraya, SkyTerra, TerreStar, ICO'
        printf 'operator\t%s\t%s\n' 'thuraya' 'GMR-1; Thuraya 2 at 98.5 east, Thuraya 3 at 44 east'
    fi
    if [[ "$want" == "all" || "$want" == "2" ]]; then
        printf 'spec\t%s\t%s\t%s\n' 'gmr-2' 'ETSI TS 101 377' 'Inmarsat IsatPhone, ACeS'
    fi
    printf 'band\t%s\t%s\n' 'service' '1525 to 1560 MHz downlink, 1626.5 to 1660.5 MHz uplink, left-hand circular spot beams'
    printf 'channel\t%s\t%s\n' '1087 ARFCN pairs' '31.25 kHz raster'
    printf 'symbol_rate\t%s\t%s\n' '23.4 kbaud base' 'the network is fully synchronous, so nothing here waits for a random access burst to align itself'
    printf 'burst\t%s\t%s\n' '2, 3, 6 or 9 slots' 'one burst spans multiple slots, which is not the terrestrial GSM case'
    printf 'modulation\t%s\t%s\n' 'pi/4-CQPSK and pi/4-CBPSK' '6-PSK carries the broadcast channel, pi/4-DBPSK the random access channel'
    printf 'modulation\t%s\t%s\n' 'pi/2-CBPSK, 16-APSK, 32-APSK' 'GmPRS and GMR-1 3G, at 1x, 2x, 4x and 5x the base symbol rate'
    printf 'sync\t%s\t%s\n' 'dual chirp over three slots' 'the frequency correction channel is a chirp, not a burst of a known pattern'
    printf 'layer2\t%s\t%s\n' 'LAPSat' 'a link layer of its own, not LAPDm'
    printf 'codec\t%s\t%s\n' 'AMBE derived' 'a compatible decoder family exists; the speech is not GSM full rate'
    printf 'security\t%s\t%s\n' 'cipher optional at layer 1' 'supposedly derived from A5/2, but neither A5/1 nor A5/2 as published; a network may run without it'
    printf 'rach\t%s\t%s\n' 'in the clear' 'the channel request carries the reason, the dialled number and the terminal position'
    printf 'feeder\t%s\t%s\n' 'C band 3.4 to 4.2 GHz down and 5.85 to 6.725 GHz up, Ku 12 to 18 GHz' 'the standard does not specify the feeder modulation'
    printf 'geometry\t%s\t%s\n' '35786 km, 119.3 ms one way' 'a bent-pipe round trip lands at roughly 239 to 280 ms'
    printf 'ref\t%s\t%s\n' 'osmocom GMR introduction' 'the public reverse engineering summary this table follows'
    printf 'limit\t%s\t%s\n' 'a description, not a decoder' 'nothing here demodulates a GMR burst, and no cipher is implemented'
    printf 'verdict\t%s\n' 'gmr_air_interface_described'
    return 0
}

ntn_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    near() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3" tol="$4"
        awk -v g="$got" -v w="$want" -v t="$tol" -v n="$n" 'BEGIN{
            d = g-w; if (d < 0) d = -d
            if (d <= t) printf "%s\tPASS\n", n
            else { printf "%s\tFAIL want=%s got=%s delta=%.8f tol=%s\n", n, w, g, d, t; exit 1 }
        }' || bad=$(( bad + 1 ))
    }

    local d
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    trap 'rm -rf "$d"' EXIT
    export LOOT_DIR="$d/loot" CAPTURES_DIR="$d/captures" STATE_DIR="$d/state"
    export NTN_DIR="$d/loot/ntn"
    mkdir -p "$NTN_DIR"

    # 1. Doppler: 2 GHz carrier, 7500 m/s closing, 0 deg -> 50.03 kHz.
    chk dop-fd    "$(fld "$(ntn_doppler 2000000000 7500 0)" doppler_hz)" "50034.6"
    chk dop-zero  "$(fld "$(ntn_doppler 2000000000 7500 90)" doppler_hz)" "0.0"
    chk dop-neg   "$(fld "$(ntn_doppler 2000000000 7500 180)" doppler_hz)" "-50034.6"
    chk dop-bad   "$(ntn_doppler x 1 0 >/dev/null 2>&1; echo $?)" "2"

    # 2. Round-trip delay: GEO ~238.7 ms, LEO 600 km ~4.00 ms.
    chk rtt-geo "$(fld "$(ntn_range_rtt 35786)" rtt_ms)" "238.738"
    chk rtt-leo "$(fld "$(ntn_range_rtt 600)" rtt_ms)" "4.003"
    chk rtt-bad "$(ntn_range_rtt x >/dev/null 2>&1; echo $?)" "2"

    # 3. TA units: LEO 600 km needs ~7685 LTE TA units, far past the 1282 cap.
    chk ta-leo "$(fld "$(ntn_ta_units 600)" ta_units)" "7685"
    chk ta-over "$(fld "$(ntn_ta_units 600)" note)" "exceeds the LTE TA command range — NTN needs the extended offset in SIB19"
    chk ta-unit "$(fld "$(ntn_ta_units 600)" lte_ta_max)" "1282"
    # a terrestrial-range distance stays inside the range, so the branch is real.
    chk ta-short "$(fld "$(ntn_ta_units 1)" note)" "within the LTE TA command range"

    # 4. K_offset. The unit is 15 kHz reference slots (TS 38.331 V18.3.0
    #    NTN-Config field description), and one such slot is 1 ms (TS 38.211
    #    Table 4.3.2-1: at mu=0 there is 1 slot per 1 ms subframe). So
    #    K_offset=1 is 1.000 ms and K_offset=239 is 239.000 ms; at 30.72 MS/s
    #    239 ms is 7,342,080 samples. The carrier SCS does not change the
    #    delay, it changes the slot count: TS 38.213 V18.4.0 clause 9 has the
    #    UE add 2^(mu-mu_Koffset)*K_offset slots of the active UL BWP with
    #    mu_Koffset = 0 in FR1 and FR2-NTN, so SCS 30/60/120 kHz turns 239
    #    reference slots into 478/956/1912 carrier slots of 0.5/0.25/0.125 ms.
    chk koffset-one   "$(fld "$(ntn_koffset 1)" delay_ms)"                 "1.000"
    chk koffset-slot  "$(fld "$(ntn_koffset 1)" slot_ms_used)"             "1.000"
    chk koffset-unit  "$(fld "$(ntn_koffset 1)" k_offset_unit)"            "slots at 15 kHz reference (TS 38.331 NTN-Config)"
    chk koffset-geo   "$(fld "$(ntn_koffset 239)" delay_ms)"               "239.000"
    chk koffset-samp  "$(fld "$(ntn_koffset 239 15 30720000)" delay_samples)" "7342080"
    chk koffset-a30   "$(fld "$(ntn_koffset 239 30)" applied_slots)"       "478"
    chk koffset-a60   "$(fld "$(ntn_koffset 239 60)" applied_slots)"       "956"
    chk koffset-a120  "$(fld "$(ntn_koffset 239 120)" applied_slots)"      "1912"
    chk koffset-cslot "$(fld "$(ntn_koffset 239 30)" carrier_slot_ms)"     "0.500"
    chk koffset-c120  "$(fld "$(ntn_koffset 239 120)" carrier_slot_ms)"    "0.125"
    chk koffset-a30ms "$(fld "$(ntn_koffset 239 30)" applied_ms)"          "239.000"
    chk koffset-120ms "$(fld "$(ntn_koffset 239 120)" delay_ms)"           "239.000"
    chk koffset-zero  "$(ntn_koffset 0 >/dev/null 2>&1; echo $?)"          "2"
    chk koffset-max   "$(ntn_koffset 1024 >/dev/null 2>&1; echo $?)"       "2"
    chk koffset-dec   "$(ntn_koffset 12.5 >/dev/null 2>&1; echo $?)"       "2"
    chk koffset-scs   "$(ntn_koffset 1 7 >/dev/null 2>&1; echo $?)"        "2"
    chk koffset-rate  "$(ntn_koffset 1 15 0 >/dev/null 2>&1; echo $?)"     "2"

    # 5. SIB19 decodes through the generated NR table; the feeder link is still
    #    refused, because SIB19 carries no gateway geometry for it to use.
    chk sib19-nobits  "$(ntn_sib19 >/dev/null 2>&1; echo $?)"              "2"
    chk sib19-why     "$(ntn_sib19 2>&1 >/dev/null | grep -c '^WHY')"      "1"
    # A vector whose answer is known by construction: pycrate encodes a SIB19
    # carrying t-Service-r17 = 4294967296 as 46 bits, padded to 200400000000.
    chk sib19-tsvc    "$(ntn_sib19 200400000000 2>/dev/null | awk -F'\t' '$1=="t-Service-r17"{print $2}')" "4294967296"
    chk sib19-bits    "$(ntn_sib19 200400000000 2>/dev/null | awk -F'\t' '$1=="bits_read"{print $2}')"      "46"
    # An all-absent SIB19 is legal (every component is OPTIONAL, 7 bits), so
    # the refusal case has to be a bit string that is not hex at all.
    chk sib19-badhex  "$(ntn_sib19 zz >/dev/null 2>&1; echo $?)"           "1"
    chk feeder-answers "$(ntn_feeder_link >/dev/null 2>&1; echo $?)"      "0"

    # 9. SIB19 build: the element encodes, and its own decoder reads it back.
    local b19; b19=$(ntn_sib19_build --koffset 20 --epoch-sfn 3 --epoch-sub 5 --validity s30 --kmac 2 --ref-hex AABBCC --dist 1000)
    chk sib19-build-rc "$?" "0"
    chk sib19-build-bits "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="bits"{print $2}')" "102"
    chk sib19-build-readback "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="read_back"{print $2}')" "yes"
    chk sib19-build-koffset "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="koffset"{print $2}')" "20"
    chk sib19-build-ref "$(printf '%s\n' "$b19" | awk -F'\t' '$1=="reference_location"{print $2}')" "0xAABBCC"
    local hx; hx=$(printf '%s\n' "$b19" | awk -F'\t' '$1=="hex"{print $2}')
    chk sib19-decode-koffset "$(ntn_sib19 "$hx" | awk -F'\t' '$1=="ntn-Config-r17.cellSpecificKoffset-r17"{print $2}')" "20"
    chk sib19-decode-validity "$(ntn_sib19 "$hx" | awk -F'\t' '$1 ~ /ntn-UlSyncValidityDuration/{print $2}')" "s30"
    chk sib19-bad-koffset "$(ntn_sib19_build --koffset 5000 >/dev/null 2>&1; echo $?)" "2"
    chk sib19-bad-kmac "$(ntn_sib19_build --kmac 0 >/dev/null 2>&1; echo $?)" "2"
    chk sib19-bad-flag "$(ntn_sib19_build --nonsense >/dev/null 2>&1; echo $?)" "2"
    # The carrier: SIB19 never arrives alone, so the envelope is built too and
    # its own decoder has to give the value back.
    local car; car=$(ntn_sib19_carrier --ref-hex AABBCC)
    chk carrier-rc "$?" "0"
    chk carrier-bits "$(printf '%s\n' "$car" | awk -F'\t' '$1=="bits"{print $2}')" "104"
    chk carrier-readback "$(printf '%s\n' "$car" | awk -F'\t' '$1=="read_back"{print $2}')" "yes"
    chk carrier-alt "$(printf '%s\n' "$car" | awk -F'\t' '$1=="sib_alternative"{print $2}')" "sib19-v1700"
    chk carrier-wrapper "$(printf '%s\n' "$car" | awk -F'\t' '$1=="sib_wrapper" && $2 ~ /sib-TypeAndInfo/{print "nested"}')" "nested"
    chk carrier-scheduled "$(printf '%s\n' "$car" | awk -F'\t' '$1=="scheduled_as" && $2 ~ /sibType19/{print "named"}')" "named"
    chk carrier-period "$(printf '%s\n' "$car" | awk -F'\t' '$1=="si_periodicity"{print $2}')" "rf64"
    chk carrier-bad-period "$(ntn_sib19_carrier --period rf7 >/dev/null 2>&1; echo $?)" "2"
    chk carrier-bad-koffset "$(ntn_sib19_carrier --koffset 0 >/dev/null 2>&1; echo $?)" "2"
    # and the envelope decodes back to the same SIB19 fields
    local chx; chx=$(printf '%s\n' "$car" | awk -F'\t' '$1=="hex"{print $2}')
    chk carrier-decode-koffset "$(python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools/nr_rrc.py" decode SystemInformation "$chx" 2>/dev/null | awk -F'\t' '$1 ~ /cellSpecificKoffset/{print $2}')" "20"
    chk carrier-decode-sib "$(python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tools/nr_rrc.py" decode SystemInformation "$chx" 2>/dev/null | awk -F'\t' '$1 ~ /^criticalExtensions[.]systemInformation[.]sib-TypeAndInfo\[0\][.]sib19-v1700/ {f=1} END{print f+0}')" "1"
    # 10. Hostile ephemeris: the timing a forged SIB19 leaves the UE with.
    local eh; eh=$(ntn_ephemeris_hijack --true-range 1200 --forged-range 600 --koffset 20 --koffset-error 3 --scs 30)
    chk eph-ta-err "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="ta_error_us"{print $2}')" "-4002.8"
    chk eph-half "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="ta_error_half_us"{print $2}')" "-2001.4"
    chk eph-cp-finding "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="finding" && $2=="timing_beyond_cp"{print $3}')" "HIGH"
    chk eph-koffset-ms "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="koffset_error_ms"{print $2}')" "1.500"
    chk eph-k-finding "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="finding" && $2=="koffset_mismatch"{print $3}')" "HIGH"
    chk eph-verdict "$(printf '%s\n' "$eh" | awk -F'\t' '$1=="verdict"{print $2}')" "ephemeris_hostile"
    chk eph-within-cp "$(ntn_ephemeris_hijack --true-range 1200 --forged-range 1199.9 --koffset 20 | awk -F'\t' '$1=="finding" && $2=="timing_within_cp"{print $3}')" "INFO"
    chk eph-noargs "$(ntn_ephemeris_hijack --true-range 1200 >/dev/null 2>&1; echo $?)" "2"
    chk eph-bad-scs "$(ntn_ephemeris_hijack --true-range 1 --forged-range 2 --koffset 20 --scs 45 >/dev/null 2>&1; echo $?)" "2"
    # 11. Timing advance to a position: one circle, then two circles.
    local gl; gl=$(ntn_timing_geoloc --ta 12000 --sat-lat 48 --sat-lon 11 --sat-alt 600)
    chk geo-slant "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="slant_range_km"{print $2}')" "936.9"
    chk geo-radius "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="ground_radius_km"{print $2}')" "719.5"
    chk geo-verdict "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="verdict"{print $2}')" "position_circle_only"

    local sp fp
    sp=$(ntn_scan_plan)
    fp=$(ntn_fakecell_plan)
    chk resel-verdict "$(ntn_reselect --terrestrial-rsrp -105 --satellite-rsrp -95 | awk -F'\t' '$1=="verdict"{print $2}')" "reselection_to_satellite"
    chk resel-marginal "$(ntn_reselect --terrestrial-rsrp -95 --satellite-rsrp -94 | awk -F'\t' '$1=="verdict"{print $2}')" "marginal_inside_hysteresis"
    chk resel-barred "$(ntn_reselect --terrestrial-rsrp -80 --satellite-rsrp -120 --barred | awk -F'\t' '$1=="verdict"{print $2}')" "reselection_to_satellite_when_S_passes"
    chk resel-s-crit "$(ntn_reselect --terrestrial-rsrp -105 --satellite-rsrp -95 | awk -F'\t' '$1=="criterion" && $2=="S_satellite"{print $3}')" "pass"
    chk scan-plan-status "$(printf '%s\n' "$sp" | awk -F'\t' '$1=="status"{print $2}')" "plan"
    chk scan-plan-sib19 "$(printf '%s\n' "$sp" | grep -c "SIB19")" "5"
    chk scan-plan-signals "$(printf '%s\n' "$sp" | grep -c '^signal')" "4"
    chk fake-plan-locks "$(printf '%s\n' "$fp" | awk -F'\t' '$1=="finding" && $2=="three_locks"{print $3}')" "HIGH"
    chk fake-plan-licensed "$(printf '%s\n' "$fp" | grep -c "licensed to that operator")" "1"
    chk fake-plan-steps "$(printf '%s\n' "$fp" | grep -c '^step')" "3"
    chk geo-single "$(printf '%s\n' "$gl" | awk -F'\t' '$1=="finding" && $2=="single_measurement"{print $3}')" "MEDIUM"
    local g2; g2=$(ntn_timing_geoloc --range-km 620 --sat-lat 48 --sat-lon 11 --sat-alt 600 --range2-km 665 --sat2-lat 51 --sat2-lon 14)
    chk geo-candidates "$(printf '%s\n' "$g2" | grep -c '^candidate')" "2"
    chk geo-pinned "$(printf '%s\n' "$g2" | awk -F'\t' '$1=="verdict"{print $2}')" "position_pinned_to_two_points"
    chk geo-noargs "$(ntn_timing_geoloc --sat-lat 1 --sat-lon 1 --sat-alt 600 >/dev/null 2>&1; echo $?)" "2"
    chk geo-noalt "$(ntn_timing_geoloc --ta 100 >/dev/null 2>&1; echo $?)" "2"
    # 6. Behind the satellite: the carrier chain, the encryption layers, the kit.
    chk bh-chain "$(ntn_backhaul chain | grep -c '^chain')"                 "6"
    chk bh-demod "$(fld "$(ntn_backhaul chain)" demodulate)"                "no"
    chk bh-chain-verdict "$(fld "$(ntn_backhaul chain)" verdict)"           "feeder_chain_described"
    chk bh-crypto-link "$(ntn_backhaul crypto | awk -F'\t' '$1=="layer" && $2=="link"{print $3}')" "10 percent of transponders scrambled"
    chk bh-crypto-ops "$(ntn_backhaul crypto | grep -c '^operator')"        "7"
    chk bh-crypto-verdict "$(fld "$(ntn_backhaul crypto)" verdict)"         "encryption_layers_named"
    chk bh-kit-total "$(ntn_backhaul kit | awk -F'\t' '$1=="kit" && $2=="total"{print $4}')" "620"
    chk bh-kit-verdict "$(fld "$(ntn_backhaul kit)" verdict)"               "passive_station_costed"
    chk bh-bad "$(ntn_backhaul radio >/dev/null 2>&1; echo $?)"             "2"
    chk gmr-specs "$(ntn_gmr | grep -c '^spec')"                            "2"
    chk gmr-one "$(ntn_gmr 1 | grep -c '^spec')"                            "1"
    chk gmr-security "$(ntn_gmr | awk -F'\t' '$1=="security"{print $2}')"   "cipher optional at layer 1"
    chk gmr-verdict "$(fld "$(ntn_gmr)" verdict)"                           "gmr_air_interface_described"
    chk gmr-bad "$(ntn_gmr 4 >/dev/null 2>&1; echo $?)"                     "2"
    printf 'SIP/2.0 200 OK\nINVITE sip:1234@10.0.0.1 SIP/2.0\nDNP3 function 5\ncommunity=public\nTLSv1.3 record\n' > "$d/fc.txt"
    chk bh-triage-found "$(ntn_backhaul_triage "$d/fc.txt" | awk -F'\t' '$1=="found"{print $2}')" "5"
    chk bh-triage-verdict "$(fld "$(ntn_backhaul_triage "$d/fc.txt")" verdict)" "feeder_capture_shows_cleartext"
    printf 'nothing to see here\n' > "$d/fc-clean.txt"
    chk bh-triage-clean "$(fld "$(ntn_backhaul_triage "$d/fc-clean.txt")" verdict)" "nothing_readable_in_this_file"
    chk bh-triage-noarg "$(ntn_backhaul_triage >/dev/null 2>&1; echo $?)"   "2"
    chk bh-triage-nofile "$(ntn_backhaul_triage "$d/nope.txt" >/dev/null 2>&1; echo $?)" "1"
    # ── the orbit: SGP4 against the published verification states ──
    # 1. The canonical verification case 88888. The expected numbers below are
    #    the published ones for SGP4 with the WGS-72 constants; the older
    #    Spacetrack Report #3 listing gives 2328.97048951 for the same element set
    #    because it uses a different constant set, which is exactly the kind of
    #    difference a self-comparison would never reveal.
    cat > "$d/v1.tle" <<'TLE'
1 88888U          80275.98708465  .00073094  13844-3  66816-4 0    87
2 88888  72.8435 115.9689 0086731  52.6988 110.5714 16.05824518  1058
TLE
    local out
    out=$(ntn_sgp4 "$(ntn_tle_get "$d/v1.tle" 1)" "$(ntn_tle_get "$d/v1.tle" 2)" 0)
    near sgp4-88888-x "$(printf '%s' "$out" | sed -n 1p | cut -f1)" 2328.96975262 0.001
    near sgp4-88888-y "$(printf '%s' "$out" | sed -n 1p | cut -f2)" -5995.22051338 0.001
    near sgp4-88888-z "$(printf '%s' "$out" | sed -n 1p | cut -f3)" 1719.97297192 0.001
    near sgp4-88888-vx "$(printf '%s' "$out" | sed -n 2p | cut -f1)" 2.912073281 0.001
    near sgp4-88888-vy "$(printf '%s' "$out" | sed -n 2p | cut -f2)" -0.983417956 0.001
    near sgp4-88888-vz "$(printf '%s' "$out" | sed -n 2p | cut -f3)" -7.090816210 0.001

    # At t = 0 no drag term contributes, so a state that matches only at the
    # epoch proves the elements were read and nothing else. 120 minutes in, the
    # node drag term and the secular rates are all in play: this is the assertion
    # that would have caught a wrong node coefficient.
    out=$(ntn_sgp4 "$(ntn_tle_get "$d/v1.tle" 1)" "$(ntn_tle_get "$d/v1.tle" 2)" 120)
    near sgp4-88888-t120-x "$(printf '%s' "$out" | sed -n 1p | cut -f1)" 1020.69234558 0.001
    near sgp4-88888-t120-y "$(printf '%s' "$out" | sed -n 1p | cut -f2)" 2286.56260634 0.001
    near sgp4-88888-t120-z "$(printf '%s' "$out" | sed -n 1p | cut -f3)" -6191.55565927 0.001

    # 2. Vallado's verification case 00005, a second independent reference.
    cat > "$d/v2.tle" <<'TLE'
1 00005U 58002B   00179.78495062  .00000023  00000-0  28098-4 0  4753
2 00005  34.2682 348.7242 1859667 331.7664  19.3264 10.82419157413667
TLE
    out=$(ntn_sgp4 "$(ntn_tle_get "$d/v2.tle" 1)" "$(ntn_tle_get "$d/v2.tle" 2)" 0)
    near sgp4-00005-x "$(printf '%s' "$out" | sed -n 1p | cut -f1)" 7022.46529266 0.001
    near sgp4-00005-y "$(printf '%s' "$out" | sed -n 1p | cut -f2)" -1400.08296755 0.001
    near sgp4-00005-z "$(printf '%s' "$out" | sed -n 1p | cut -f3)" 0.03995155 0.001
    near sgp4-00005-vx "$(printf '%s' "$out" | sed -n 2p | cut -f1)" 1.893841015 0.001
    out=$(ntn_sgp4 "$(ntn_tle_get "$d/v2.tle" 1)" "$(ntn_tle_get "$d/v2.tle" 2)" 360)
    near sgp4-00005-t360-x "$(printf '%s' "$out" | sed -n 1p | cut -f1)" -7154.03120202 0.001
    near sgp4-00005-t360-y "$(printf '%s' "$out" | sed -n 1p | cut -f2)" -3783.17682504 0.001
    near sgp4-00005-t360-z "$(printf '%s' "$out" | sed -n 1p | cut -f3)" -3536.19412294 0.001

    # 3. TLE parsing: the checksum is a mod-10 over the line, '-' counting 1.
    chk tle-checksum-l1 "$(ntn_tle_checksum "$(ntn_tle_get "$d/v1.tle" 1)")" "7"
    chk tle-checksum-l2 "$(ntn_tle_checksum "$(ntn_tle_get "$d/v1.tle" 2)")" "8"
    out=$(ntn_tle_parse "$d/v1.tle")
    chk tle-verdict "$(fld "$out" verdict)" "parsed"
    chk tle-epoch-year "$(fld "$out" epoch-year)" "1980"
    chk tle-epoch-utc "$(fld "$out" epoch-utc)" "1980-10-01T23:41:24Z"
    chk tle-eccentricity "$(fld "$out" eccentricity)" "0.0086731"
    chk tle-inclination "$(fld "$out" inclination-deg)" "72.8435"
    chk tle-period "$(fld "$out" period-min)" "89.6736"
    chk tle-guard-no-tle "$(ntn_tle_parse "$d/nothing.tle" >/dev/null 2>&1; echo $?)" "2"

    # 4. Deep space is refused by name, not propagated with the wrong model.
    printf '1 99999U 58002B   00179.78495062  .00000023  00000-0  28098-4 0  4753\n2 99999  34.2682 348.7242 1859667 331.7664  19.3264  1.00270000  1234\n' > "$d/geo.tle"
    out=$(ntn_sgp4 "$(ntn_tle_get "$d/geo.tle" 1)" "$(ntn_tle_get "$d/geo.tle" 2)" 0)
    chk deep-space-guard "$(printf '%s' "$out" | grep -c 'deep-space-element-set')" "1"

    # 5. Epoch arithmetic: the pivot, and a leap year.
    chk epoch-1999 "$(ntn_epoch_iso 1999 1.0)" "1999-01-01T00:00:00Z"
    chk epoch-leap  "$(ntn_epoch_iso 2000 60.0)" "2000-02-29T00:00:00Z"
    chk epoch-2026 "$(ntn_epoch_iso 2026 1.0)" "2026-01-01T00:00:00Z"

    # 6. Range to a known geometry: the 88888 state at epoch is 6644 km out, so
    #    the one-way delay is that over c.
    out=$(ntn_sgp4_report "$d/v1.tle" 0)
    chk sgp4-report-radius "$(printf '%s\n' "$out" | awk -F'\t' '$1=="radius-km"{printf "%.1f", $2}')" "6657.7"
    chk sgp4-report-altitude "$(printf '%s\n' "$out" | awk -F'\t' '$1=="altitude-km"{printf "%.1f", $2}')" "279.6"

    # 7. TA conversion: 0.5208 us per step, and the round trip is twice the delay.
    local tau; tau=$(awk -v c="$NTN_C_KM_S" 'BEGIN{printf "%.4f", 2*(1000/c)*1e6}')
    chk ta-roundtrip-1000km "$tau" "6671.2819"
    chk ta-step "$NTN_TA_STEP_US" "0.5208"
    chk ta-command-1000km "$(awk -v rt="$tau" -v s="$NTN_TA_STEP_US" 'BEGIN{printf "%d", rt/s}')" "12809"

    # 8. Doppler sign: a closing satellite raises the received frequency.
    local dop; dop=$(awk -v f=1900000000 -v rr=-7.0 -v c="$NTN_C_KM_S" 'BEGIN{printf "%.0f", -1*f*rr/c}')
    chk doppler-closing-positive "$(awk -v d="$dop" 'BEGIN{print (d>0)?"approaching":"receding"}')" "approaching"
    chk doppler-7kms "$dop" "44364"

    # 9. Footprint: the horizon radius from 273 km is about 1,900 km, and a
    #    10-degree floor shrinks it.
    out=$(ntn_footprint "$d/v1.tle" 0 0)
    local r0 r10
    r0=$(printf '%s\n' "$out" | awk -F'\t' '$1=="radius-km"{print $2}')
    out=$(ntn_footprint "$d/v1.tle" 0 10)
    r10=$(printf '%s\n' "$out" | awk -F'\t' '$1=="radius-km"{print $2}')
    chk footprint-horizon-sane "$(awk -v r="$r0" 'BEGIN{print (r>1300 && r<2200)?"sane":"off"}')" "sane"
    chk footprint-floor-shrinks "$(awk -v a="$r0" -v b="$r10" 'BEGIN{print (b<a)?"shrinks":"grows"}')" "shrinks"
    chk footprint-bbox-order "$(printf '%s\n' "$out" | awk -F'\t' '
        $1=="bbox-lat-min"{a=$2} $1=="bbox-lat-max"{b=$2} END{print (a<b)?"ordered":"inverted"}')" "ordered"

    # 10. NTN config: the field plan names the timers it cannot derive.
    out=$(ntn_config_plan "$d/v1.tle" 0)
    chk ntn-ephemeris "$(fld "$out" ephemerisType)" "positionVelocityECEF"
    chk ntn-inclination "$(printf '%s\n' "$out" | awk -F'\t' '$1=="inclination-deg"{print $2}')" "72.8435"
    chk ntn-sma-sane "$(printf '%s\n' "$out" | awk -F'\t' '$1=="semiMajorAxis-km"{printf "%d", ($2>6600 && $2<6700)}')" "1"
    chk ntn-sync-unobserved "$(printf '%s\n' "$out" | grep -c 'ntn-Ul-Sync-Validity	unobserved')" "1"
    chk ntn-encoding-unobserved "$(printf '%s\n' "$out" | grep -c 'wire-encoding	unobserved')" "1"

    # 11. Regulatory: no outline means unobserved, never "inside".
    out=$(ntn_regulatory "$d/v1.tle" 0 10 "001-01" "")
    chk reg-no-outline "$(fld "$out" verdict)" "unobserved"
    chk reg-no-outline-exit "$(ntn_regulatory "$d/v1.tle" 0 10 "001-01" "" >/dev/null 2>&1; echo $?)" "1"
    out=$(ntn_regulatory "$d/v1.tle" 0 10 "001-01" "-90,-180,90,180")
    chk reg-whole-world "$(fld "$out" verdict)" "inside-licensed"

    # 12. Store-and-forward: a polar LEO from a mid-latitude point over 3 hours
    #     must show some coverage and therefore a worst gap.
    out=$(ntn_store_forward 52.0 13.4 "$d/v1.tle" 3 10)
    chk sf-verdict-present "$(printf '%s\n' "$out" | grep -c '^verdict')" "1"
    chk sf-gap-numeric "$(printf '%s\n' "$out" | awk -F'\t' '$1=="worst-gap-s"{print ($2 ~ /^[0-9]+$/)?"numeric":"bad"}')" "numeric"

    # 12b. The feeder link. The gateway sees the same satellite the service link
    #      does, so the geometry is ntn_look from the other end; the budget is
    #      the two numbers a bent-pipe transponder answers to; the capture margin
    #      is a ratio of two flux densities, i.e. of two EIRPs and two ranges.
    out=$(ntn_feeder_budget 30 35786 70)
    near fb-fspl   "$(fld "$out" path_loss_db)"          213.07 0.02
    near fb-spread "$(fld "$out" spreading_loss_db)"     162.07 0.02
    near fb-flux   "$(fld "$out" flux_density_dbw_m2)"   -92.07 0.02
    near fb-sat    "$(fld "$out" saturation_margin_db)"    2.07 0.02
    near fb-cn0    "$(fld "$out" cn0_db_hz)"              85.53 0.02
    chk  fb-verdict    "$(fld "$out" verdict)"            "nominal"
    chk  fb-sfd-src    "$(fld "$out" sfd_source)"         "assumed: -90 dBW/m2, a typical bent-pipe saturation flux"
    # the same carrier from a LEO slant range drives the transponder past
    # saturation, because 800 km is nearer the satellite than the gateway is
    out=$(ntn_feeder_budget 28 800 55)
    chk  fb-leo-verdict "$(fld "$out" verdict)"           "saturated"
    near fb-leo-sat     "$(fld "$out" saturation_margin_db)" -15.95 0.02
    chk  fb-bad-range   "$(ntn_feeder_budget 30 zero 70 >/dev/null 2>&1; echo $?)" "2"
    chk  fb-bad-eirp    "$(ntn_feeder_budget 30 35786 xx >/dev/null 2>&1; echo $?)" "2"

    out=$(ntn_feeder_look 0 105 "$d/v2.tle" 25 30)
    chk  fl-aos        "$(fld "$out" aos_min)"            "0.00"
    chk  fl-los        "$(fld "$out" los_min)"            "9.00"
    chk  fl-visible    "$(fld "$out" visible_samples)"    "19"
    near fl-maxel      "$(fld "$out" max_elev_deg)"       86.516 0.01
    near fl-first-rng  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0.00"{print $2}')" 783.827 0.01
    near fl-first-fspl "$(printf '%s\n' "$out" | awk -F'\t' '$1=="0.00"{print $8}')" 179.88 0.01
    # a gateway on the wrong side of the planet sees nothing, and says so
    out=$(ntn_feeder_look 0 -11 "$d/v2.tle" 25 30)
    chk  fl-nopass     "$(fld "$out" visible_samples)"    "0"
    chk  fl-nopass-el  "$(fld "$out" max_elev_deg)"       "unobserved"
    chk  fl-noargs     "$(ntn_feeder_look '' '' '' >/dev/null 2>&1; echo $?)" "2"

    out=$(ntn_feeder_capture "$d/v2.tle" 0 0 105 --gw-lat 25 --gw-lon 95 --dish-m 3.7 --freq-mhz 30)
    chk  fc-gateway    "$(fld "$out" gateway_source)"     "supplied"
    near fc-adv        "$(fld "$out" geometry_advantage_db)" -12.30 0.02
    near fc-required   "$(fld "$out" required_eirp_dbw)"   57.70 0.02
    near fc-dish-gain  "$(fld "$out" dish_gain_dbi)"       59.44 0.02
    near fc-tx-w       "$(fld "$out" required_tx_w)"        0.670 0.01
    chk  fc-verdict    "$(fld "$out" verdict)"            "favourable"
    near fc-visible    "$(fld "$out" visible_minutes)"      7.5 0.01
    near fc-maxel      "$(fld "$out" max_elev_deg)"        86.516 0.01
    # with no gateway the ratio cannot be formed, and the row says so rather
    # than assuming a site
    out=$(ntn_feeder_capture "$d/v2.tle" 0 0 105)
    chk  fc-nogw-src   "$(fld "$out" gateway_source)"     "not-supplied"
    chk  fc-nogw-req   "$(fld "$out" required_eirp_dbw)"  "unobserved"
    chk  fc-nogw-verdict "$(fld "$out" verdict)"          "gateway-unknown"
    # an interferer under a satellite it cannot see has no window at all
    out=$(ntn_feeder_capture "$d/v2.tle" 0 0 -20 --gw-lat 40 --gw-lon -75)
    chk  fc-nopass     "$(fld "$out" verdict)"            "no-pass"
    near fc-nopass-vis "$(fld "$out" visible_minutes)"      0.0 0.01
    chk  fc-bad-lat    "$(ntn_feeder_capture "$d/v2.tle" 0 north 105 >/dev/null 2>&1; echo $?)" "2"
    chk  fc-bad-gw     "$(ntn_feeder_capture "$d/v2.tle" 0 0 105 --gw-lat 25 >/dev/null 2>&1; echo $?)" "2"
    chk  fc-unknown    "$(ntn_feeder_capture "$d/v2.tle" 0 0 105 --nope 1 >/dev/null 2>&1; echo $?)" "2"

    out=$(ntn_feeder_link)
    chk  feeder-bands     "$(printf '%s\n' "$out" | grep -c '^Ka	')" "1"
    chk  feeder-payloads  "$(printf '%s\n' "$out" | grep -c '^payload	')" "2"
    chk  feeder-unsignalled "$(printf '%s\n' "$out" | grep -c '^not-signalled	gateway')" "1"

    # 13. Guards name what is missing, and the plan is a handoff.
    chk guard-pass-noargs "$(ntn_pass_plan '' '' '' >/dev/null 2>&1; echo $?)" "2"
    chk guard-doppler-noargs "$(ntn_doppler_pass '' '' '' >/dev/null 2>&1; echo $?)" "2"
    chk guard-footprint-noargs "$(ntn_footprint "$d/none.tle" >/dev/null 2>&1; echo $?)" "2"
    chk plan-handoff "$(ntn_plan | grep -c '^status	handoff')" "1"
    chk status-transmit "$(ntn_status_tsv | grep -c '^TRANSMIT	none')" "1"

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

ntn_menu() {
    while true; do
        banner
        echo "  === 5G NTN / Satellite ==="
        echo
        cat <<'M'
  [1]  Doppler shift
  [2]  Round-trip delay
  [3]  TA units
  [4]  K_offset (slots -> ms, samples)
  [5]  SIB19 decode (TS 38.331)
  [6]  Feeder link (refused: no geometry)
  [7]  Plan (handoff)
  [8]  Behind the satellite (feeder carrier)
  [9]  Legacy satellite cellular (GMR)
  [10] Element set (TLE) parse
  [11] Propagate (SGP4) to a time
  [12] Pass plan (AOS / LOS / max elevation)
  [13] Doppler across a pass
  [14] Timing advance across a pass
  [15] Footprint / licence boundary
  [16] Store-and-forward coverage
  [0]  back
M
        read -rp "  choice> " c || return 0
        case "$c" in
            1) read -rp "  carrier Hz> " f; read -rp "  velocity m/s> " v; read -rp "  angle deg> " a
               ntn_doppler "$f" "$v" "${a:-0}"; read -rp "  enter " _ ;;
            2) read -rp "  one-way km> " k; ntn_range_rtt "$k"; read -rp "  enter " _ ;;
            3) read -rp "  one-way km> " k; ntn_ta_units "$k"; read -rp "  enter " _ ;;
            4) read -rp "  k_offset slots> " k; read -rp "  scs kHz [15/30/60/120]> " s; read -rp "  sample rate Hz (blank skips)> " r
               ntn_koffset "$k" "$s" "$r"; read -rp "  enter " _ ;;
            5) read -rp "  SIB19 as hex> " _s19; ntn_sib19 "$_s19"; read -rp "  enter " _ ;;
            6) ntn_feeder_link
               read -rp "  [l]ook angles, [b]udget, [c]apture, or enter for the inventory> " _f
               case "$_f" in
                 l) read -rp "  gateway lat> " la; read -rp "  gateway lon> " lo
                    read -rp "  element set file> " f; read -rp "  carrier MHz [30]> " mh
                    ntn_feeder_look "$la" "$lo" "$f" 15 "${mh:-30}" ;;
                 b) read -rp "  feeder MHz [30]> " mh; read -rp "  range km [35786]> " rk
                    read -rp "  EIRP dBW [70]> " ep; read -rp "  bandwidth kHz [36]> " bw
                    ntn_feeder_budget "${mh:-30}" "${rk:-35786}" "${ep:-70}" "${bw:-36}" 0 -90 ;;
                 c) read -rp "  element set file> " f; read -rp "  minutes past epoch> " t
                    read -rp "  attacker lat> " la; read -rp "  attacker lon> " lo
                    read -rp "  gateway lat (blank skips)> " gla; read -rp "  gateway lon> " glo
                    if [[ -n "$gla" ]]; then
                        ntn_feeder_capture "$f" "${t:-0}" "$la" "$lo" --gw-lat "$gla" --gw-lon "$glo"
                    else
                        ntn_feeder_capture "$f" "${t:-0}" "$la" "$lo"
                    fi ;;
                 *) ntn_feeder_link ;;
               esac
               read -rp "  enter " _ ;;
            7) ntn_plan; read -rp "  enter " _ ;;
            8) read -rp "  chain, crypto or kit> " b; ntn_backhaul "${b:-chain}"; read -rp "  enter " _ ;;
            9) read -rp "  GMR generation [1/2/all]> " g; ntn_gmr "${g:-all}"; read -rp "  enter " _ ;;
            10) read -rp "  element set file> " f; ntn_tle_parse "$f"; read -rp "  enter " _ ;;
            11) read -rp "  element set file> " f; read -rp "  minutes past epoch> " t
                ntn_sgp4_report "$f" "${t:-0}"; read -rp "  enter " _ ;;
            12) read -rp "  lat> " la; read -rp "  lon> " lo; read -rp "  element set file> " f
                ntn_pass_plan "$la" "$lo" "$f"; read -rp "  enter " _ ;;
            13) read -rp "  lat> " la; read -rp "  lon> " lo; read -rp "  element set file> " f
                read -rp "  carrier MHz> " mh
                ntn_doppler_pass "$la" "$lo" "$f" "${mh:-1900}"; read -rp "  enter " _ ;;
            14) read -rp "  lat> " la; read -rp "  lon> " lo; read -rp "  element set file> " f
                ntn_ta_schedule "$la" "$lo" "$f"; read -rp "  enter " _ ;;
            15) read -rp "  element set file> " f; read -rp "  minutes> " t; read -rp "  elevation floor> " el
                read -rp "  PLMN (blank skips)> " pl; read -rp "  outline lat1,lon1,lat2,lon2> " bb
                ntn_regulatory "$f" "${t:-0}" "${el:-10}" "$pl" "$bb"; read -rp "  enter " _ ;;
            16) read -rp "  lat> " la; read -rp "  lon> " lo; read -rp "  element set file> " f
                read -rp "  hours> " hh
                ntn_store_forward "$la" "$lo" "$f" "${hh:-12}"; read -rp "  enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

ntn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  ntn_status_tsv ;;
        --doppler)     ntn_doppler "${1:-}" "${2:-}" "${3:-0}" ;;
        --range)       ntn_range_rtt "${1:-}" ;;
        --ta)          ntn_ta_units "${1:-}" ;;
        --koffset)     ntn_koffset "${1:-}" "${2:-}" "${3:-}" ;;
        --sib19)       ntn_sib19 "${1:-}" ;;
        --sib19-carrier) ntn_sib19_carrier "$@" ;;
        --sib19-build) ntn_sib19_build "$@" ;;
        --ephemeris-hijack) ntn_ephemeris_hijack "$@" ;;
        --timing-geoloc)  ntn_timing_geoloc "$@" ;;
        --scan-plan)      ntn_scan_plan ;;
        --ntn-reselect)   ntn_reselect "$@" ;;
        --fakecell-plan)  ntn_fakecell_plan ;;
        --feeder)      ntn_feeder_link ;;
        --feeder-look) ntn_feeder_look "${1:-}" "${2:-}" "${3:-}" "${4:-15}" "${5:-30}" ;;
        --feeder-budget) ntn_feeder_budget "${1:-30}" "${2:-35786}" "${3:-70}" "${4:-36}" "${5:-0}" "${6:--90}" ;;
        --feeder-capture) ntn_feeder_capture "$@" ;;
        --backhaul)    ntn_backhaul "${1:-chain}" ;;
        --backhaul-triage) ntn_backhaul_triage "${1:-}" ;;
        --gmr)         ntn_gmr "${1:-all}" ;;
        --plan)        ntn_plan ;;
        --tle-parse)      ntn_tle_parse "${1:-}" ;;
        --sgp4)           ntn_sgp4_report "${1:-}" "${2:-0}" ;;
        --pass-plan)      ntn_pass_plan "${1:-}" "${2:-}" "${3:-}" "${4:-12}" "${5:-0}" ;;
        --doppler-pass)   ntn_doppler_pass "${1:-}" "${2:-}" "${3:-}" "${4:-1900}" "${5:-10}" ;;
        --ta-schedule)    ntn_ta_schedule "${1:-}" "${2:-}" "${3:-}" "${4:-10}" ;;
        --footprint)      ntn_footprint "${1:-}" "${2:-0}" "${3:-10}" ;;
        --ntn-config)     ntn_config_plan "${1:-}" "${2:-0}" ;;
        --store-forward)  ntn_store_forward "${1:-}" "${2:-}" "${3:-}" "${4:-12}" "${5:-10}" ;;
        --regulatory-check) ntn_regulatory "${1:-}" "${2:-0}" "${3:-10}" "${4:-}" "${5:-}" ;;
        --selftest)    ntn_selftest ;;
        --menu)        ntn_menu ;;
        *)
            cat >&2 <<EOF
5G NTN / Satellite — propagation, Doppler, TA and SIB19

Usage: $0 COMMAND
  --status-tsv              module state as TSV
  --doppler <hz> <mps> [deg]   Doppler shift for a closing velocity
  --range <one_way_km>      one-way and round-trip delay
  --ta <one_way_km>         TA units needed vs the LTE TA range
  --koffset <slots> [scs_khz] [sample_rate_hz]   K_offset (TS 38.331, 15 kHz reference slots) -> ms and samples
  --ntn-reselect            which cell the UE reselects to, and the lever that moves it
  --scan-plan               what to listen for, and the three signals that say NTN
  --fakecell-plan           what broadcasting a satellite cell needs, and where it fails
  --timing-geoloc (--ta N | --range-km KM) --sat-lat DEG --sat-lon DEG --sat-alt KM
                            one range gives a circle; two give the pair of ground points
  --ephemeris-hijack --true-range KM --forged-range KM --koffset N
                            a forged SIB19 ephemeris, and the timing the UE derives from it
  --sib19-build [--koffset N] [--epoch-sfn N] [--epoch-sub N] [--validity sN]
                            build the SIB19-r17 element and encode it
  --sib19 <hex>             decode a SIB19 (TS 38.331) from its bits
  --feeder                  the feeder bands, the two payload kinds, and what
                            the broadcast does and does not say about the ground
  --feeder-look <gw-lat> <gw-lon> <tle> [minutes] [MHz]
                            the gateway's own view of the satellite: range,
                            elevation, azimuth, range-rate, Doppler, path loss
                            across the pass
  --feeder-budget <freq-mhz> <range-km> <eirp-dbw> [bw-khz] [g-over-t] [sfd]
                            the uplink in the two numbers a bent-pipe transponder
                            answers to: flux density against its saturation flux,
                            and the carrier-to-noise the same carrier produces
  --feeder-capture <tle> <tsince> <atk-lat> <atk-lon>
      [--gw-lat D --gw-lon D] [--gw-eirp-dbw D] [--target-js-db D]
      [--freq-mhz D] [--dish-m D] [--eff D] [--window-min N]
                            two slant ranges and two EIRPs give the carrier
                            ratio at the transponder; the EIRP a given J/S needs,
                            the geometry advantage against the gateway, and the
                            pass window the geometry allows at all
  --backhaul <chain|crypto|kit>
                            behind the satellite: the feeder carrier layers,
                            the measured encryption layers, the receive-kit cost
  --backhaul-triage <file>  classify a text export of a feeder capture
  --gmr <1|2|all>           the legacy satellite air interface reference
  --plan                    NTN handoff plan
  --tle-parse <file>        fixed-column element-set parse: epoch, elements, checksums
  --sgp4 <file> [tsince]    propagate to N minutes past the epoch (SGP4, near-earth)
  --pass-plan <lat> <lon> <file> [hours] [min-el]   AOS/LOS/max-elevation schedule
  --doppler-pass <lat> <lon> <file> [MHz] [minutes]  range, range-rate, doppler, delay
  --ta-schedule <lat> <lon> <file> [minutes]         timing advance against time
  --footprint <file> [tsince] [min-el]   the illuminated circle and its bounding box
  --ntn-config <file> [tsince]           the ephemeris fields a cell would broadcast
  --store-forward <lat> <lon> <file> [hours] [min-el]  coverage duty cycle, worst gap
  --regulatory-check <file> [tsince] [min-el] [plmn] [lat1,lon1,lat2,lon2]
                            does the footprint stay inside a licensed outline
  --selftest                verify the timing geometry and the orbit arithmetic
  --menu                    interactive menu
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    ntn_cli_main "$@"
fi
