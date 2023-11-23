node {
    try {
        stage('Clone repo') {
            checkout scm
        }
        stage('Deploy') {
            if (env.BRANCH_NAME == 'conformance') {
                ebsi_conformance_deploy("clone_repo": false)
            } else {
                ebsi_fast_deploy("clone_repo": false)
            }
        }
    } catch (e) {
        throw e
    } finally {
        cleanWs()
        dir("${env.WORKSPACE}@script") {
            deleteDir()
        }
    }
}
