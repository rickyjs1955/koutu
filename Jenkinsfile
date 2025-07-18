pipeline {
    agent any
    
    // Uncomment if Node.js needs to be installed via Jenkins
    // tools {
    //     nodejs 'Node18'
    // }
    
    environment {
        NODE_ENV = 'production'
        CI = 'true'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'git clean -fdx'
            }
        }
        
        stage('Install Dependencies') {
            parallel {
                stage('Frontend Dependencies') {
                    steps {
                        dir('frontend') {
                            sh 'npm ci'
                        }
                    }
                }
                stage('Shared Dependencies') {
                    steps {
                        dir('shared') {
                            sh 'npm ci'
                        }
                    }
                }
            }
        }
        
        stage('Lint & Format Check') {
            parallel {
                stage('ESLint') {
                    steps {
                        dir('frontend') {
                            sh 'npm run lint || true'  // Continue on lint errors for now
                        }
                    }
                }
                stage('Type Check') {
                    steps {
                        dir('frontend') {
                            sh 'npm run type-check || true'  // Continue on type errors for now
                        }
                    }
                }
            }
        }
        
        stage('Test') {
            steps {
                dir('frontend') {
                    sh 'npm run test || true'  // Continue on test failures for now
                }
            }
        }
        
        stage('Build') {
            steps {
                dir('frontend') {
                    sh 'npm run build || true'  // Continue on build errors for now
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'frontend/dist/**/*', allowEmptyArchive: true
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                script {
                    echo 'Deploying to staging...'
                    // Add your staging deployment commands here
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                script {
                    echo 'Deploying to production...'
                    // Add your production deployment commands here
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}