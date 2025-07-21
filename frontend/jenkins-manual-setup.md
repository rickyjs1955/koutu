# Jenkins Manual Setup Guide for Koutu Project

Since the automated script is having Java version conflicts, follow these manual steps in the Jenkins UI:

## 1. Install Plugins

1. Go to **Manage Jenkins** → **Manage Plugins**
2. Click on **Available** tab
3. Search and select these plugins:
   - ✅ **NodeJS Plugin**
   - ✅ **GitHub Integration Plugin**
   - ✅ **Pipeline**
   - ✅ **Git**
   - ✅ **GitHub Branch Source**
   - ✅ **Pipeline: Stage View**
   - ✅ **Blue Ocean** (optional, for better UI)
   - ✅ **Workspace Cleanup Plugin**
   - ✅ **Timestamper**

4. Click **Install without restart**
5. Check **Restart Jenkins when installation is complete**

## 2. Configure Node.js

After Jenkins restarts:

1. Go to **Manage Jenkins** → **Global Tool Configuration**
2. Scroll to **NodeJS** section
3. Click **Add NodeJS**
4. Configure:
   - **Name**: `Node18`
   - **Version**: `NodeJS 18.19.0` (or latest 18.x)
   - ✅ Check **Install automatically**
5. Click **Save**

## 3. Create Pipeline Job

1. From Jenkins dashboard, click **New Item**
2. Enter name: `Koutu-Frontend-Pipeline`
3. Select **Pipeline**
4. Click **OK**

## 4. Configure Pipeline

In the pipeline configuration:

1. **Description**: `Koutu Fashion App - Frontend CI/CD Pipeline`

2. Under **Build Triggers**:
   - ✅ Check **Poll SCM**
   - Schedule: `H/5 * * * *` (every 5 minutes)

3. Under **Pipeline**, select **Pipeline script from SCM**:
   - **SCM**: Git
   - **Repository URL**: `https://github.com/YOUR_USERNAME/koutu.git`
   - **Branch**: `*/main`
   - **Script Path**: `Jenkinsfile`

4. Click **Save**

## 5. Create Jenkinsfile

The Jenkinsfile has been created at: `/home/monmonmic/koutu/Jenkinsfile`

Make sure to:
1. Update the GitHub repository URL in the Jenkinsfile
2. Commit it to your repository

## 6. Run Your First Build

1. Go to your pipeline: http://localhost:8081/job/Koutu-Frontend-Pipeline/
2. Click **Build Now**
3. Watch the build progress in **Console Output**

## 7. Set Up GitHub Webhook (Optional)

For automatic builds on push:

1. In your GitHub repository, go to **Settings** → **Webhooks**
2. Click **Add webhook**
3. Configure:
   - **Payload URL**: `http://YOUR_SERVER_IP:8081/github-webhook/`
   - **Content type**: `application/json`
   - **Events**: Select **Just the push event**
4. Click **Add webhook**

## 📝 Notes

- The Jenkinsfile includes stages for: Checkout, Install, Lint, Test, Build, Deploy
- It has parallel execution for faster builds
- Includes branch-specific deployment (develop → staging, main → production)
- Archives build artifacts automatically

## 🚀 Quick Commands

Monitor Jenkins:
```bash
./jenkins-monitor.sh
```

Start Jenkins:
```bash
./start-jenkins.sh
```

View Jenkinsfile:
```bash
cat /home/monmonmic/koutu/Jenkinsfile
```