project(
    'bandicoot',
    ['cpp'],
    version: '0.1',
    default_options: [
        'prefix=/usr',
        'cpp_std=c++20',
        'warning_level=3',
        'buildtype=debugoptimized',
    ]
)

inc = include_directories('src')

crashdir = get_option('prefix') / get_option('localstatedir') / get_option('crashdir')

cdata = configuration_data()
cdata.set_quoted('CRASH_DIR', crashdir)
cdata.set_quoted('SOCKET_PATH', get_option('socket-path'))

configure_file(output: 'config.hh', configuration: cdata)

zstd = dependency('libzstd', required: true)
scdoc = dependency('scdoc', required: get_option('man'))

executable(
    'bandicootd',
    'src/bandicootd.cc',
    include_directories: inc,
    install: true,
    install_dir: get_option('libexecdir'),
    dependencies: [zstd],
)

executable(
    'bandicoot-dump',
    'src/bandicoot-dump.cc',
    include_directories: inc,
    install: true,
    install_dir: get_option('libexecdir'),
)

executable(
    'bandicoot',
    'src/bandicoot.cc',
    include_directories: inc,
    install: true,
    install_dir: get_option('bindir'),
)

sysname = get_option('sysctl-name')

if sysname != ''
    syscdata = configuration_data()

    clpath = get_option('prefix') / get_option('libexecdir') / 'bandicoot-dump'
    syscdata.set('BANDICOOT_CLIENT', clpath)

    configure_file(
        input: 'data/sysctl.conf.in',
        output: sysname,
        configuration: syscdata,
        format: 'cmake@',
        install: true,
        install_dir: get_option('libdir') / 'sysctl.d',
        install_mode: 'rwxr-xr-x',
    )
endif
