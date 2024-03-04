pipeline {
    agent {
        label 'windows'
    }

    environment {
        SNYK = tool name: 'Snyk-Installation'
        SNYK_API_TOKEN = credentials('Snyk-API-Token')
    }

    parameters {
        booleanParam(name: 'OWASP_DEPENDENCY_CHECK', defaultValue: false, description: 'Enable OWASP Dependency Check')
        booleanParam(name: 'SNYK', defaultValue: false, description: 'Enable Snyk Scan')
        booleanParam(name: 'TRIVY', defaultValue: false, description: 'Enable Trivy Scan')
    }
    
    stages {
        stage('Build') {
            steps {
                echo 'Build'
            }
        }

        stage('Test') {
            steps {
                echo 'Test'
            }
        }

        stage('OWASP Dependency Check') {
            when {
                expression { params.OWASP_DEPENDENCY_CHECK == true }
            }
            steps {
                dependencyCheck additionalArguments: '--scan \"${WORKSPACE}\" --prettyPrint --format JSON --format XML', odcInstallation: 'Dependency-Check-Installation'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }

        stage('Snyk') {
            when {
                expression { params.SNYK == true }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'SUCCESS') {
                    bat """
                        ${SNYK}/snyk-win.exe auth %SNYK_API_TOKEN%
                        ${SNYK}/snyk-win.exe code test ${WORKSPACE} --json-file-output=${WORKSPACE}/snyk-report.json
                    """
                }
            }
        }

        stage('Trivy') {
            when {
                expression { params.TRIVY == true }
            }
            steps {
                bat """
                    cd C:\\jenkins\\trivy_0.49.0_windows-64bit
                    trivy.exe
                    trivy fs --scanners vuln,secret,config,license ${WORKSPACE} -f json -o ${WORKSPACE}/trivy-report.json
                """
            }
        }

        stage('Deploy') {
            steps {
                echo 'Deploy'
            }
        }

        stage('Clean Workspace') {
            steps {
                echo "cleanWs()"
            }
        }
    }

    post {
        always {
            emailext(
                to: 'ahdoo.ling010519@gmail.com',
                mimeType: 'text/html',
                subject: 'Build #${BUILD_NUMBER} - ${JOB_NAME}',
                body: """
                    <html>
                        <head>
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    background-color: #f5f5f5;
                                }
                                .container {
                                    background-color: #ffffff;
                                    border-radius: 5px;
                                    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.2);
                                    margin: 20px;
                                    padding: 20px;
                                }
                                table {
                                    width: 100%;
                                    border-collapse: collapse;
                                    margin-top: 20px;
                                }
                                th, td {
                                    border: 1px solid #ddd;
                                    padding: 8px;
                                    text-align: left;
                                }
                                th {
                                    background-color: #f2f2f2;
                                }
                                .status {
                                    font-size: 24px;
                                    font-weight: bold;
                                    color: ${getStatusColor()};
                                }
                                .footer {
                                    margin-top: 20px;
                                    padding-top: 10px;
                                    border-top: 1px solid #ddd;
                                    text-align: center;
                                    font-size: 12px;
                                    color: #666;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <p class="status">Build Status: ${currentBuild.currentResult}</p>
                                <h3>Build Info</h3>
                                <table>
                                    <tr>
                                        <th>Job Name</th>
                                        <td>${JOB_NAME}</td>
                                        <th>Build Number</th>
                                        <td>${BUILD_NUMBER}</td>
                                    </tr>
                                    <tr>
                                        <th>Build URL</th>
                                        <td colspan="3"><a href="${BUILD_URL}">${BUILD_URL}</a></td>
                                    </tr>
                                    <tr>
                                        <th>Build Node</th>
                                        <td>${NODE_NAME}</td>
                                        <th>Build Duration</th>
                                        <td>${currentBuild.durationString}</td>
                                    </tr>
                                </table>
     
                                <h3>Git Changeset</h3>
                                <table>
                                    <tr>
                                        <th>Commit ID</th>
                                        <th>Author</th>
                                        <th>Message</th>
                                        <th>Files</th>
                                        <th>Timestamp</th>
                                    </tr>
                                    ${getGitChangeSetTable()}
                                </table>

                                <h3>OWASP Dependency Check</h3>
                                <table>
                                </table>

                                <h3>Snyk</h3>
                                <table>
                                </table>

                                <h3>Trivy</h3>
                                <table>
                                </table>
                            </div>
                            <div class="footer">
                                <p>
                                    This email and any files transmitted with it are confidential and intended solely for the use of the individual or entity to whom they are addressed. If you have received this email in error, please notify the system manager.
                                    <br><br>
                                    This message is sent from the AVAR project.
                                    <br><br>
                                    &copy; 2024 All rights reserved.
                                </p>
                            </div>
                        </body>
                    </html>
                """
            )
        }
    }
}

def getGitChangeSetTable() {
    def changelogTable = ""
    def build = currentBuild

    if (build.changeSets.size() > 0) {
        changelogTable += build.changeSets.collect { cs ->
            cs.collect { entry ->
                def formattedTimestamp = new Date(entry.timestamp.toLong()).toString()
                def id = entry.commitId
                def files = entry.affectedFiles.collect { file ->
                    file.path
                }.join(", ")
                def author = entry.author.fullName
                def message = entry.msg
                def commitUrl = "https://github.com/SHAODOO/WebGoat/commit/${id}"
                "<tr><td><a href=\"${commitUrl}\">${id}</a></td><td>${author}</td><td>${message}</td><td>${files}</td><td>${formattedTimestamp}</td></tr>"
            }.join('\n')
        }.join('\n')
    } else {
        def buildsWithChangeset = 0
        while (buildsWithChangeset < 5 && build != null) {
            if (build.changeSets.size() > 0) {
                changelogTable += build.changeSets.collect { cs ->
                    cs.collect { entry ->
                        def formattedTimestamp = new Date(entry.timestamp.toLong()).toString()
                        def id = entry.commitId
                        def files = entry.affectedFiles.collect { file ->
                            file.path
                        }.join(", ")
                        def author = entry.author.fullName
                        def message = entry.msg
                        // Construct GitHub commit URL
                        def commitUrl = "https://github.com/SHAODOO/WebGoat/commit/${id}"
                        "<tr><td><a href=\"${commitUrl}\">${id}</a></td><td>${author}</td><td>${message}</td><td>${files}</td><td>${formattedTimestamp}</td></tr>"
                    }.join('\n')
                }.join('\n')
                buildsWithChangeset++
            }
            build = build.previousBuild
        }
    }

    if (changelogTable.isEmpty()) {
        changelogTable = "<tr><td colspan=\"5\">No changesets found</td></tr>"
    }

    return changelogTable
}

def getStatusColor() {
    switch (currentBuild.currentResult) {
        case 'SUCCESS':
            return 'green';
        case 'FAILURE':
            return 'red';
        case 'ABORTED':
            return 'grey';
        default:
            return 'black'; // default color
    }
}

