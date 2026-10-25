# The version has exactly one home: ../VERSION, next to imsisting.sh. The CLI
# reads the same file, so the GUI label and `--version` can no longer drift --
# they did: the CLI said v0.4 while this file said 0.1.0.
project(
  'imsisting-native',
  'c',
  version: run_command(
    'cat', meson.current_source_dir() / '..' / 'VERSION',
    check: true,
  ).stdout().strip(),
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=false',
  ],
)

# ------------------------------------------------------------------ #
#  Generate config.h with the absolute project root baked in.        #
#  Lets the toolkit be built and run from any directory: the root    #
#  is resolved at configure time, not guessed at runtime.            #
# ------------------------------------------------------------------ #

_imsisting_root = run_command(
  'dirname', meson.current_source_dir(),
  check: true,
).stdout().strip()

conf = configuration_data()
conf.set('IMSISTING_ROOT', _imsisting_root)
conf.set('IMSISTING_VERSION', meson.project_version())


gnome = import('gnome')
cc = meson.get_compiler('c')

gtk_dep = dependency('gtk4', version: '>=4.10')

# VTE gives the GUI a real terminal for module output. It is optional:
# without it the output pane falls back to a text view, so the build
# still succeeds on a system that has GTK4 but no vte4.
vte_dep = dependency('vte-2.91-gtk4', required: false)

# config.h has to agree with what the dependency probes decided: without this
# the VTE include is skipped and the terminal button falls back to whatever
# terminal the desktop has instead of using the library that is installed.
if vte_dep.found()
  conf.set('HAVE_VTE', 1)
endif

configure_file(
  input: 'src/config.h.in',
  output: 'config.h',
  configuration: conf,
)

# Orbitron and Neuropol are compiled into the binary. fontconfig is what lets
# this process see them without a system-wide install; GTK already uses it.
fontconfig_dep = dependency('fontconfig')

imsisting_resources = gnome.compile_resources(
  'imsisting-resources',
  'resources/imsisting.gresource.xml',
  source_dir: 'resources',
  c_name: 'imsisting',
  # The manifest names the files, so meson has no other way to learn that the
  # sheet changed: without this a CSS-only edit is silently not embedded, and
  # the running app keeps the old styles with nothing to say so.
  dependencies: files('resources/style.css'),
)

executable(
  'imsisting-gui',
  [
    'src/main1.c',
    # The Help page. Its own translation unit because it is a body of
    # reference text that changes for reasons unrelated to the rest of the
    # interface, and because it needs nothing from it: no AppState, no
    # module registry, no output console.
    'src/help_page.c',
    # The Map page. Its own translation unit for the same reason: a canvas, a
    # projection and a layer inbox, and nothing from AppState but the root.
    'src/map_page.c',
    'src/fleet_page.c',
    'src/stats_chart.c',
    # The target panel's posture chips. Its own translation unit because the
    # rules it applies — which cipher is weak, which store beats which — are
    # testable without a display, and a panel this dense changes for reasons
    # that have nothing to do with main1.c.
    'src/target_posture.c',
    imsisting_resources,
  ],
  dependencies: [
    gtk_dep,
    vte_dep,
    fontconfig_dep,
    # The Map page's projection: cos/floor/pow for the scale bar and the
    # graticule step. GTK does not pull the maths library in on its own.
    cc.find_library('m', required: false),
  ],
  install: true,
)
