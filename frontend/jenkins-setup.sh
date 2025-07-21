#!/bin/bash

# Jenkins CI/CD Setup Script for Koutu Project
# This script automates the complete Jenkins setup process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
JENKINS_URL="http://localhost:8081"
JENKINS_CLI_JAR="/tmp/jenkins-cli.jar"
ADMIN_PASSWORD_FILE="/home/monmonmic/.jenkins/secrets/initialAdminPassword"
JAVA_17="/usr/lib/jvm/java-17-openjdk-amd64/bin/java"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to wait for Jenkins to be ready
wait_for_jenkins() {
    print_status "Waiting for Jenkins to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$JENKINS_URL/login" > /dev/null 2>&1; then
            print_success "Jenkins is ready!"
            return 0
        fi
        print_status "Attempt $attempt/$max_attempts - Jenkins not ready yet, waiting..."
        sleep 10
        ((attempt++))
    done
    
    print_error "Jenkins failed to start after $max_attempts attempts"
    return 1
}

# Function to get admin password
get_admin_password() {
    if [ -f "$ADMIN_PASSWORD_FILE" ]; then
        cat "$ADMIN_PASSWORD_FILE"
    else
        print_error "Admin password file not found: $ADMIN_PASSWORD_FILE"
        print_warning "Please provide the admin password manually"
        read -s -p "Enter Jenkins admin password: " password
        echo "$password"
    fi
}

# Function to download Jenkins CLI
download_jenkins_cli() {
    print_status "Downloading Jenkins CLI..."
    if ! curl -s -o "$JENKINS_CLI_JAR" "$JENKINS_URL/jnlpJars/jenkins-cli.jar"; then
        print_error "Failed to download Jenkins CLI"
        return 1
    fi
    print_success "Jenkins CLI downloaded"
}

# Function to install plugins
install_plugins() {
    print_status "Installing Jenkins plugins..."
    
    local plugins=(
        "nodejs"
        "github"
        "pipeline-github-lib"
        "workflow-aggregator"
        "git"
        "github-branch-source"
        "pipeline-stage-view"
        "blueocean"
        "docker-workflow"
        "build-timeout"
        "credentials-binding"
        "timestamper"
        "ws-cleanup"
        "ant"
        "gradle"
    )
    
    for plugin in "${plugins[@]}"; do
        print_status "Installing plugin: $plugin"
        if ! $JAVA_17 -jar "$JENKINS_CLI_JAR" -s "$JENKINS_URL" -auth "admin:$ADMIN_PASSWORD" install-plugin "$plugin" -deploy; then
            print_warning "Failed to install plugin: $plugin (may already be installed)"
        fi
    done
    
    print_success "Plugin installation completed"
}

# Function to restart Jenkins
restart_jenkins() {
    print_status "Restarting Jenkins to activate plugins..."
    $JAVA_17 -jar "$JENKINS_CLI_JAR" -s "$JENKINS_URL" -auth "admin:$ADMIN_PASSWORD" restart
    
    # Wait for restart
    sleep 30
    wait_for_jenkins
    print_success "Jenkins restarted successfully"
}

# Function to configure Node.js
configure_nodejs() {
    print_status "Configuring Node.js tool..."
    
    # Create Node.js tool configuration
    cat > /tmp/nodejs-config.xml << 'EOF'
<?xml version='1.1' encoding='UTF-8'?>
<jenkins.plugins.nodejs.tools.NodeJSInstallation_-DescriptorImpl plugin="nodejs@1.6.1">
  <installations>
    <jenkins.plugins.nodejs.tools.NodeJSInstallation>
      <name>Node18</name>
      <home></home>
      <properties>
        <jenkins.plugins.nodejs.tools.NodeJSInstallation_-PropertyImpl>
          <installer class="jenkins.plugins.nodejs.tools.NodeJSInstaller">
            <id>18.19.0</id>
          </installer>
        </jenkins.plugins.nodejs.tools.NodeJSInstallation_-PropertyImpl>
      </properties>
    </jenkins.plugins.nodejs.tools.NodeJSInstallation>
  </installations>
</jenkins.plugins.nodejs.tools.NodeJSInstallation_-DescriptorImpl>
EOF

    # Apply configuration using Jenkins CLI
    $JAVA_17 -jar "$JENKINS_CLI_JAR" -s "$JENKINS_URL" -auth "admin:$ADMIN_PASSWORD" create-node < /tmp/nodejs-config.xml || true
    
    print_success "Node.js configured"
}

# Function to create Jenkinsfile
create_jenkinsfile() {
    print_status "Creating Jenkinsfile for Koutu project..."
    
    cat > /home/monmonmic/koutu/Jenkinsfile << 'EOF'
pipeline {
    agent any
    
    tools {
        nodejs 'Node18'
    }
    
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
                            sh 'npm run lint'
                        }
                    }
                }
                stage('Type Check') {
                    steps {
                        dir('frontend') {
                            sh 'npm run type-check'
                        }
                    }
                }
                stage('Format Check') {
                    steps {
                        dir('frontend') {
                            sh 'npm run format:check'
                        }
                    }
                }
            }
        }
        
        stage('Test') {
            parallel {
                stage('Unit Tests') {
                    steps {
                        dir('frontend') {
                            sh 'npm run test:unit'
                        }
                    }
                    post {
                        always {
                            publishTestResults testResultsPattern: 'frontend/test-results.xml'
                        }
                    }
                }
                stage('Integration Tests') {
                    steps {
                        dir('frontend') {
                            sh 'npm run test:integration'
                        }
                    }
                }
            }
        }
        
        stage('Build') {
            steps {
                dir('frontend') {
                    sh 'npm run build'
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'frontend/dist/**/*', allowEmptyArchive: true
                }
            }
        }
        
        stage('Build Analysis') {
            steps {
                dir('frontend') {
                    sh 'npm run analyze'
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                script {
                    // Deploy to staging environment
                    sh 'echo "Deploying to staging..."'
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
                    // Deploy to production environment
                    sh 'echo "Deploying to production..."'
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
            script {
                if (env.BRANCH_NAME == 'main') {
                    echo 'Production deployment successful!'
                } else if (env.BRANCH_NAME == 'develop') {
                    echo 'Staging deployment successful!'
                } else {
                    echo 'Build successful!'
                }
            }
        }
        failure {
            script {
                echo 'Build failed!'
                // Add notification logic here (Slack, email, etc.)
            }
        }
        unstable {
            echo 'Build unstable!'
        }
        changed {
            echo 'Build status changed!'
        }
    }
}
EOF

    print_success "Jenkinsfile created at /home/monmonmic/koutu/Jenkinsfile"
}

# Function to create pipeline job
create_pipeline_job() {
    print_status "Creating Koutu Frontend Pipeline job..."
    
    cat > /tmp/koutu-pipeline-config.xml << 'EOF'
<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <actions>
    <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobAction plugin="pipeline-model-definition@1.8.5"/>
    <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction plugin="pipeline-model-definition@1.8.5">
      <jobProperties/>
      <triggers/>
      <parameters/>
      <options/>
    </org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction>
  </actions>
  <description>Koutu Fashion App - Frontend CI/CD Pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties>
    <org.jenkinsci.plugins.workflow.job.properties.DisableConcurrentBuildsJobProperty/>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers>
        <hudson.triggers.SCMTrigger>
          <spec>H/5 * * * *</spec>
          <ignorePostCommitHooks>false</ignorePostCommitHooks>
        </hudson.triggers.SCMTrigger>
      </triggers>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps@2.87">
    <scm class="hudson.plugins.git.GitSCM" plugin="git@4.8.3">
      <configVersion>2</configVersion>
      <userRemoteConfigs>
        <hudson.plugins.git.UserRemoteConfig>
          <url>https://github.com/YOUR_USERNAME/koutu.git</url>
        </hudson.plugins.git.UserRemoteConfig>
      </userRemoteConfigs>
      <branches>
        <hudson.plugins.git.BranchSpec>
          <name>*/main</name>
        </hudson.plugins.git.BranchSpec>
      </branches>
      <doGenerateSubmoduleConfigurations>false</doGenerateSubmoduleConfigurations>
      <submoduleCfg class="empty-list"/>
      <extensions/>
    </scm>
    <scriptPath>Jenkinsfile</scriptPath>
    <lightweight>true</lightweight>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>
EOF

    # Create the job
    $JAVA_17 -jar "$JENKINS_CLI_JAR" -s "$JENKINS_URL" -auth "admin:$ADMIN_PASSWORD" create-job "Koutu-Frontend-Pipeline" < /tmp/koutu-pipeline-config.xml
    
    print_success "Pipeline job created: Koutu-Frontend-Pipeline"
}

# Function to create webhook setup script
create_webhook_script() {
    print_status "Creating GitHub webhook setup script..."
    
    cat > /home/monmonmic/koutu/setup-github-webhook.sh << 'EOF'
#!/bin/bash

# GitHub Webhook Setup Script
# Run this script to set up GitHub webhook for automatic builds

GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
GITHUB_REPO="YOUR_USERNAME/koutu"
JENKINS_URL="http://localhost:8081"
WEBHOOK_URL="$JENKINS_URL/github-webhook/"

echo "Setting up GitHub webhook for repository: $GITHUB_REPO"

curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web",
    "active": true,
    "events": ["push", "pull_request"],
    "config": {
      "url": "'$WEBHOOK_URL'",
      "content_type": "json",
      "insecure_ssl": "0"
    }
  }' \
  "https://api.github.com/repos/$GITHUB_REPO/hooks"

echo "Webhook setup completed!"
EOF

    chmod +x /home/monmonmic/koutu/setup-github-webhook.sh
    print_success "GitHub webhook setup script created"
}

# Function to create monitoring script
create_monitoring_script() {
    print_status "Creating Jenkins monitoring script..."
    
    cat > /home/monmonmic/koutu/jenkins-monitor.sh << 'EOF'
#!/bin/bash

# Jenkins Monitoring Script
# Use this to monitor Jenkins status and build health

JENKINS_URL="http://localhost:8081"

echo "=== Jenkins Status Monitor ==="
echo "Jenkins URL: $JENKINS_URL"
echo "Timestamp: $(date)"
echo

# Check if Jenkins is running
if curl -s "$JENKINS_URL/login" > /dev/null 2>&1; then
    echo "✅ Jenkins is running"
    
    # Get Jenkins version
    VERSION=$(curl -s -I "$JENKINS_URL" | grep -i "x-jenkins:" | cut -d' ' -f2 | tr -d '\r')
    echo "📦 Jenkins Version: $VERSION"
    
    # Check build queue
    echo "🔄 Build Queue Status:"
    curl -s "$JENKINS_URL/queue/api/json" | jq '.items[] | .task.name' 2>/dev/null || echo "No builds in queue"
    
    # Check last build status
    echo "🏗️  Last Build Status:"
    curl -s "$JENKINS_URL/job/Koutu-Frontend-Pipeline/lastBuild/api/json" | jq '.result' 2>/dev/null || echo "No builds yet"
    
else
    echo "❌ Jenkins is not running"
    echo "💡 To start Jenkins, run: ./start-jenkins.sh"
fi
EOF

    chmod +x /home/monmonmic/koutu/jenkins-monitor.sh
    print_success "Jenkins monitoring script created"
}

# Function to create Jenkins startup script
create_startup_script() {
    print_status "Creating Jenkins startup script..."
    
    cat > /home/monmonmic/koutu/start-jenkins.sh << 'EOF'
#!/bin/bash

# Jenkins Startup Script
# Use this to start Jenkins with the correct Java version

JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
JENKINS_WAR="/tmp/jenkins.war"
JENKINS_PORT="8081"

echo "Starting Jenkins with Java 17..."
echo "Java Home: $JAVA_HOME"
echo "Jenkins WAR: $JENKINS_WAR"
echo "Port: $JENKINS_PORT"

# Kill any existing Jenkins processes
pkill -f jenkins.war 2>/dev/null || true

# Start Jenkins
nohup $JAVA_HOME/bin/java -jar $JENKINS_WAR --httpPort=$JENKINS_PORT > jenkins.log 2>&1 &

echo "Jenkins starting in background..."
echo "Logs: jenkins.log"
echo "URL: http://localhost:$JENKINS_PORT"
echo "PID: $!"

# Wait a moment and check if it's running
sleep 5
if pgrep -f jenkins.war > /dev/null; then
    echo "✅ Jenkins started successfully"
else
    echo "❌ Jenkins failed to start - check jenkins.log"
fi
EOF

    chmod +x /home/monmonmic/koutu/start-jenkins.sh
    print_success "Jenkins startup script created"
}

# Main execution
main() {
    print_status "Starting Jenkins CI/CD setup for Koutu project..."
    echo "==========================================="
    
    # Check if Jenkins is running
    if ! curl -s "$JENKINS_URL/login" > /dev/null 2>&1; then
        print_error "Jenkins is not running at $JENKINS_URL"
        print_status "Please start Jenkins first and then run this script"
        exit 1
    fi
    
    # Get admin password
    ADMIN_PASSWORD=$(get_admin_password)
    if [ -z "$ADMIN_PASSWORD" ]; then
        print_error "Could not obtain admin password"
        exit 1
    fi
    
    print_success "Admin password obtained"
    
    # Wait for Jenkins to be ready
    wait_for_jenkins
    
    # Download Jenkins CLI
    download_jenkins_cli
    
    # Install plugins
    install_plugins
    
    # Restart Jenkins
    restart_jenkins
    
    # Configure Node.js
    configure_nodejs
    
    # Create Jenkinsfile
    create_jenkinsfile
    
    # Create pipeline job
    create_pipeline_job
    
    # Create additional scripts
    create_webhook_script
    create_monitoring_script
    create_startup_script
    
    print_success "Jenkins CI/CD setup completed successfully!"
    echo
    echo "==========================================="
    echo "📋 Next Steps:"
    echo "1. 🔗 Update GitHub repository URL in Jenkinsfile"
    echo "2. 🔑 Configure GitHub webhook using: ./setup-github-webhook.sh"
    echo "3. 🏗️  Run your first build: http://localhost:8081/job/Koutu-Frontend-Pipeline/"
    echo "4. 📊 Monitor Jenkins: ./jenkins-monitor.sh"
    echo "5. 🚀 Start Jenkins anytime: ./start-jenkins.sh"
    echo "==========================================="
    
    print_success "Setup complete! 🎉"
}

# Run main function
main "$@"