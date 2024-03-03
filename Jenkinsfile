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
                                    color: green;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <p class="status">Build Status: ${currentBuild.currentResult}</p>
                                <table>
                                    <tr>
                                        <th>Job Name</th>
                                        <th>Build Number</th>
                                        <th>Build Node</th>
                                        <th>Build URL</th>
                                        <th>Build Duration</th>
                                    </tr>
                                    <tr>
                                        <td>${JOB_NAME}</td>
                                        <td>${BUILD_NUMBER}</td>
                                        <td>${NODE_NAME}</td>
                                        <td><a href="${BUILD_URL}">${BUILD_URL}</a></td>
                                        <td>${currentBuild.durationString}</td>
                                    </tr>
                                    <!-- Add more rows as needed -->
                                </table>
                            </div>
                        </body>
                    </html>
                """
            )
            echo "cleanWs()"
        }
    }
}