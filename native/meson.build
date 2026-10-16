project(
  'imsisting-native',
  'c',
  version: '0.1.0',
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
    imsisting_resources,
  ],
  dependencies: [
    gtk_dep,
    vte_dep,
    fontconfig_dep,
  ],
  install: true,
)
