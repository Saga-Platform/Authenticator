pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'chmod +x ./gradlew'
                sh './gradlew build -x test'
            }
        }
        stage('Test') {
            steps {
                sh './gradlew clean test --no-daemo'
            }
            post {
                always {
                    junit '**/build/test-results/test/*.xml'
                }
            }
        }
    }
}