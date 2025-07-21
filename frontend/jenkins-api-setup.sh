#!/bin/bash

# Jenkins API Setup Script for Koutu Project
# Uses REST API instead of CLI to avoid Java version issues

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
JENKINS_URL="http://localhost:8081"
ADMIN_USER="admin"
ADMIN_PASSWORD="a695f04cb2d24c8294da5c0be87c19f5"

echo -e "${BLUE}Jenkins API Setup for Koutu Project${NC}"
echo "======================================="

# Function to install plugins via API
install_plugins() {
    echo -e "${BLUE}Installing plugins via API...${NC}"
    
    local plugins=(
        "nodejs"
        "github"
        "git"
        "workflow-aggregator"
        "pipeline-stage-view"
        "credentials-binding"
        "timestamper"
        "ws-cleanup"
    )
    
    for plugin in "${plugins[@]}"; do
        echo "Installing plugin: $plugin"
        curl -X POST \
            -u "$ADMIN_USER:$ADMIN_PASSWORD" \
            "$JENKINS_URL/pluginManager/installNecessaryPlugins" \
            -H "Content-Type: text/xml" \
            -d "<jenkins><install plugin='$plugin@latest' /></jenkins>"
    done
    
    echo -e "${GREEN}Plugin installation triggered${NC}"
    echo "Note: Plugins will install in the background. Restart Jenkins when complete."
}

# Function to create pipeline job via API
create_pipeline_job() {
    echo -e "${BLUE}Creating pipeline job...${NC}"
    
    # Create job XML
    cat > /tmp/pipeline-config.xml << 'EOF'
<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>Koutu Fashion App - Frontend CI/CD Pipeline</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition">
    <scm class="hudson.plugins.git.GitSCM">
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

    # Create job via API
    curl -X POST \
        -u "$ADMIN_USER:$ADMIN_PASSWORD" \
        "$JENKINS_URL/createItem?name=Koutu-Frontend-Pipeline" \
        -H "Content-Type: application/xml" \
        -d @/tmp/pipeline-config.xml
    
    echo -e "${GREEN}Pipeline job created!${NC}"
}

# Main execution
echo "1. Installing plugins..."
install_plugins

echo ""
echo "2. Creating pipeline job..."
create_pipeline_job

echo ""
echo -e "${GREEN}Setup partially complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Wait for plugins to install (check Manage Jenkins → Manage Plugins)"
echo "2. Restart Jenkins when plugins are installed"
echo "3. Configure Node.js in Global Tool Configuration"
echo "4. Update GitHub URL in the pipeline configuration"
echo "5. Run your first build!"
echo ""
echo "Pipeline URL: $JENKINS_URL/job/Koutu-Frontend-Pipeline/"
echo "Manual setup guide: ./jenkins-manual-setup.md"