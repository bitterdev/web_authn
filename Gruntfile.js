var packageName = "web_authn";

module.exports = function (grunt) {
    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),
        exec: {
          composer_install: {
            cmd: 'composer install'
          }
        },
        version: {
            php: {
                options: {
                    pkg: {
                        version: function () {
                            var s = grunt.file.read('controller.php');
                            var re = /\$pkgVersion[\s*]=[\s*][\'|\"](.*)[\'|\"]/g
                            var m = re.exec(s);

                            if (m.length) {
                                return m[1];
                            }

                            return false;
                        }()
                    },
                    prefix: '@version\\s*'
                },
                src: [
                    'dist/*.php', 'dist/**/*.php', 'dist/**/**/*.php', 'dist/**/**/**/*.php', 'dist/**/**/**/**/*.php'
                ]
            }
        },
        copy: {
            main: {
                files: [
                    {src: ['authentication/**'], dest: "dist/"},
                    {src: ['controllers/**'], dest: "dist/"},
                    {src: ['single_pages/**'], dest: "dist/"},
                    {src: ['vendor/**'], dest: "dist/"},
                    {src: ['elements/**'], dest: "dist/"},
                    {src: ['mail/**'], dest: "dist/"},
                    {src: ['src/**'], dest: "dist/"},
                    {src: ['controller.php'], dest: "dist/", filter: 'isFile'},
                    {src: ['icon.png'], dest: "dist/", filter: 'isFile'},
                    {src: ['INSTALL.TXT'], dest: "dist/", filter: 'isFile'},
                    {src: ['LICENSE.TXT'], dest: "dist/", filter: 'isFile'},
                    {src: ['CHANGELOG'], dest: "dist/", filter: 'isFile'},
                    {src: ['data.xml'], dest: "dist/", filter: 'isFile'},
                    {src: ['db.xml'], dest: "dist/", filter: 'isFile'}
                ]
            }
        },
        compress: {
            main: {
                options: {
                    archive: 'release/' + packageName + '.zip'
                },
                files: [
                    {src: ['**'], dest: packageName, expand: true, cwd: 'dist/'}
                ]
            }
        },
        clean: {
            dist: ['dist']
        }
    });

    grunt.loadNpmTasks('grunt-contrib-compress');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-exec');
    grunt.loadNpmTasks('grunt-version');
    grunt.loadNpmTasks('grunt-contrib-copy');

    grunt.registerTask('default', ['clean:dist', 'copy', 'version', 'compress:main', 'clean:dist']);
};
