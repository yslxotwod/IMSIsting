"""Generated unaligned-PER layout table for LTE RRC (TS 36.331).

Produced by tools/asn1gen.py -- DO NOT EDIT BY HAND.

Oracle:    pycrate 0.8.1
Generated: 2026-10-25 07:50:14

This file is plain data: it imports nothing and is consumed by
tools/lte_per.py, which implements the PER engine.

TYPES maps an ASN.1 type name to a layout node:
  ref      {t: <type name>}
  bool     {}                                  True/False, 1 bit
  null     {}                                  no bits
  int      {lb, ub, ext}                       constrained whole number
  enum     {names, ext}                        constrained index
  bits     {size, ext}                         size [N,N] == fixed
  octets   {size, ext, containing}             containing is a note only
  seq      {ext, comp, extadd}                 comp = [name, node, optional, default]
  choice   {ext, alts, extadd}                 alts = [name, node]
  seqof    {size, ext, of}
  unsupported {why}                            engine raises PerError
Extension additions are one OPEN TYPE each:
  {k: extgrp, names, node}   a group of additions, node is its seq
  {k: extone, name, node}    a lone addition, node is that component
"""

# Explicitly requested root types (--types), in the order given.
ROOTS = [
    'RANAP_PDU',
    'InitialUE_Message',
    'Paging',
    'Reset',
    'Overload',
]

# The ASN.1 family the keys in TYPES belong to.  A verifier that is
# handed this table must select that family before it indexes pycrate,
# or it answers every key from whichever family it last selected.
FAMILY = 'ranap'

# Reason strings for every construct the generator could not express.
# Keyed by the type that contains it; the engine raises PerError on them.
UNSUPPORTED = {
}

TYPES = {
    'InitialUE_Message': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'protocolIEs',
                {
                    'k': 'seqof',
                    'size': [0, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'value',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                False,
                None,
            ],
            [
                'protocolExtensions',
                {
                    'k': 'seqof',
                    'size': [1, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'extensionValue',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'InitiatingMessage': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'procedureCode',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'criticality',
                {
                    'k': 'enum',
                    'names': ['reject', 'ignore', 'notify'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'value',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'Outcome': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'procedureCode',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'criticality',
                {
                    'k': 'enum',
                    'names': ['reject', 'ignore', 'notify'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'value',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'Overload': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'protocolIEs',
                {
                    'k': 'seqof',
                    'size': [0, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'value',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                False,
                None,
            ],
            [
                'protocolExtensions',
                {
                    'k': 'seqof',
                    'size': [1, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'extensionValue',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'Paging': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'protocolIEs',
                {
                    'k': 'seqof',
                    'size': [0, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'value',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                False,
                None,
            ],
            [
                'protocolExtensions',
                {
                    'k': 'seqof',
                    'size': [1, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'extensionValue',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'RANAP_PDU': {
        'k': 'choice',
        'ext': True,
        'alts': [
            [
                'initiatingMessage',
                {
                    'k': 'ref',
                    't': 'InitiatingMessage',
                },
            ],
            [
                'successfulOutcome',
                {
                    'k': 'ref',
                    't': 'SuccessfulOutcome',
                },
            ],
            [
                'unsuccessfulOutcome',
                {
                    'k': 'ref',
                    't': 'UnsuccessfulOutcome',
                },
            ],
            [
                'outcome',
                {
                    'k': 'ref',
                    't': 'Outcome',
                },
            ],
        ],
        'extadd': [],
    },
    'Reset': {
        'k': 'seq',
        'ext': True,
        'comp': [
            [
                'protocolIEs',
                {
                    'k': 'seqof',
                    'size': [0, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'value',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                False,
                None,
            ],
            [
                'protocolExtensions',
                {
                    'k': 'seqof',
                    'size': [1, 65535],
                    'ext': False,
                    'of': {
                        'k': 'seq',
                        'ext': False,
                        'comp': [
                            [
                                'id',
                                {
                                    'k': 'int',
                                    'lb': 0,
                                    'ub': 65535,
                                    'ext': False,
                                },
                                False,
                                None,
                            ],
                            [
                                'criticality',
                                {
                                    'k': 'enum',
                                    'names': ['reject', 'ignore', 'notify'],
                                    'ext': None,
                                },
                                False,
                                None,
                            ],
                            [
                                'extensionValue',
                                {
                                    'k': 'octets',
                                    'size': None,
                                    'ext': False,
                                    'containing': None,
                                },
                                False,
                                None,
                            ],
                        ],
                        'extadd': [],
                    },
                },
                True,
                None,
            ],
        ],
        'extadd': [],
    },
    'SuccessfulOutcome': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'procedureCode',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'criticality',
                {
                    'k': 'enum',
                    'names': ['reject', 'ignore', 'notify'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'value',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
    'UnsuccessfulOutcome': {
        'k': 'seq',
        'ext': False,
        'comp': [
            [
                'procedureCode',
                {
                    'k': 'int',
                    'lb': 0,
                    'ub': 255,
                    'ext': False,
                },
                False,
                None,
            ],
            [
                'criticality',
                {
                    'k': 'enum',
                    'names': ['reject', 'ignore', 'notify'],
                    'ext': None,
                },
                False,
                None,
            ],
            [
                'value',
                {
                    'k': 'octets',
                    'size': None,
                    'ext': False,
                    'containing': None,
                },
                False,
                None,
            ],
        ],
        'extadd': [],
    },
}
