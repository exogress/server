#!/usr/bin/env groovy

IMAGE = "servers"
IMAGE_SIGNALER = "signaler"
IMAGE_GATEWAY = "gateway"
IMAGE_ASSISTANT = "assistant"
IMAGE_DIRECTOR = "director"
PUSH = false
DOCKER_AUTH = "\$(cat ~/.docker/config.json |jq -r \".auths[] .auth\")"
BASE_VERSION = ""

node("linux-docker") {
    stage("set_base_version") {
        checkout([
                $class           : 'GitSCM',
                branches         : scm.branches,
                extensions       : scm.extensions + [[$class: 'SubmoduleOption', recursiveSubmodules: true, parentCredentials: true]],
                userRemoteConfigs: scm.userRemoteConfigs
        ])
        sh("rm -rf ~/bin/toml")
        sh("mkdir -p ~/bin")
        sh("cp -f ci/toml ~/bin/")
        sh("chmod +x ~/bin/toml")
        BASE_VERSION = sh(
                script: "export PATH=\"$HOME/.cargo/bin:$HOME/bin:$PATH\" && ./lifecycle-scripts/spawn.sh current_version.sh",
                returnStdout: true
        ).trim()
    }
}
TAG = "${BASE_VERSION}.dev.nopush"

if (env.BRANCH_NAME == "master") {
    IMAGE = "r.lancastr.net/${IMAGE}"
    IMAGE_SIGNALER = "r.lancastr.net/${IMAGE_SIGNALER}"
    IMAGE_GATEWAY = "r.lancastr.net/${IMAGE_GATEWAY}"
    IMAGE_ASSISTANT = "r.lancastr.net/${IMAGE_ASSISTANT}"
    IMAGE_DIRECTOR = "r.lancastr.net/${IMAGE_DIRECTOR}"
    PUSH = true
    TAG = "${BASE_VERSION}"
} else if (env.BRANCH_NAME == "develop") {
    IMAGE = "r.lancastr.net/${IMAGE}-${env.BRANCH_NAME}"
    IMAGE_SIGNALER = "r.lancastr.net/${IMAGE_SIGNALER}-${env.BRANCH_NAME}"
    IMAGE_GATEWAY = "r.lancastr.net/${IMAGE_GATEWAY}-${env.BRANCH_NAME}"
    IMAGE_ASSISTANT = "r.lancastr.net/${IMAGE_ASSISTANT}-${env.BRANCH_NAME}"
    IMAGE_DIRECTOR = "r.lancastr.net/${IMAGE_DIRECTOR}-${env.BRANCH_NAME}"
    TAG = "${BASE_VERSION}.build.${env.BUILD_NUMBER}"
    PUSH = true
}

node("linux-docker") {
    ansiColor('xterm') {
        try {
            stage("checkout") {
                checkout([
                        $class           : 'GitSCM',
                        branches         : scm.branches,
                        extensions       : scm.extensions + [[$class: 'SubmoduleOption', recursiveSubmodules: true, parentCredentials: true]],
                        userRemoteConfigs: scm.userRemoteConfigs
                ])
            }

            stage('check_if_exist') {
                if (PUSH == true) {
                    def exists = sh(
                            script: "curl -X GET -sH \"Authorization: Basic $DOCKER_AUTH\" https://r.lancastr.net/v2/${IMAGE_SIGNALER}/tags/list | jq \"try .tags catch [] | try contains([\\\"$TAG\\\"])\"",
                            returnStdout: true
                    ).trim()
                    if (exists == "true") {
                        error('Tag is already exist')
                    }
                }
            }

            stage('build_base') {
                sh "docker build --no-cache --target=builder -t ${IMAGE}:${TAG} ."
                sh "docker tag ${IMAGE}:${TAG} ${IMAGE}:latest"
            }

            stage('build_signaler') {
                sh "docker build  --target=signaler -t ${IMAGE_SIGNALER}:${TAG} ."
                sh "docker tag ${IMAGE_SIGNALER}:${TAG} ${IMAGE_SIGNALER}:latest"
            }

            stage('build_gateway') {
                sh "docker build  --target=gateway -t ${IMAGE_GATEWAY}:${TAG} ."
                sh "docker tag ${IMAGE_GATEWAY}:${TAG} ${IMAGE_GATEWAY}:latest"
            }

            stage('build_assistant') {
                sh "docker build  --target=assistant -t ${IMAGE_ASSISTANT}:${TAG} ."
                sh "docker tag ${IMAGE_ASSISTANT}:${TAG} ${IMAGE_ASSISTANT}:latest"
            }

            stage('build_director') {
                sh "docker build  --target=director -t ${IMAGE_DIRECTOR}:${TAG} ."
                sh "docker tag ${IMAGE_DIRECTOR}:${TAG} ${IMAGE_DIRECTOR}:latest"
            }

            stage('save_artifacts') {
                if (PUSH == true) {
                    sh "docker push $IMAGE_SIGNALER:$TAG"
                    sh "docker push $IMAGE_SIGNALER:latest"

                    sh "docker push $IMAGE_GATEWAY:$TAG"
                    sh "docker push $IMAGE_GATEWAY:latest"

                    sh "docker push $IMAGE_ASSISTANT:$TAG"
                    sh "docker push $IMAGE_ASSISTANT:latest"

                    sh "docker push $IMAGE_DIRECTOR:$TAG"
                    sh "docker push $IMAGE_DIRECTOR:latest"
                }
            }
            if (currentBuild.getPreviousBuild()?.getResult() != "SUCCESS") {
                slackSend channel: '#dev',
                        color: 'good',
                        message: "${IMAGE.capitalize()} branch ${env.BRANCH_NAME} (${env.BUILD_NUMBER}) has repaired and ready (<${env.JOB_URL}|Open>)"
            }
            // slackSend channel: '#core-services',
            //           color: 'good',
            //           message: "${IMAGE.capitalize()} branch ${env.BRANCH_NAME} (${env.BUILD_NUMBER}) is ready (<${env.JOB_URL}|Open>)"
        } catch (e) {
            if (currentBuild.getPreviousBuild()?.getResult() == "SUCCESS") {
                slackSend channel: '#dev',
                        color: 'danger',
                        message: "${IMAGE.capitalize()} branch ${env.BRANCH_NAME} (${env.BUILD_NUMBER}) is now broken (<${env.JOB_URL}|Open>)"
            }
            currentBuild.result = "FAILED"
            throw e
        } finally {
            stage("cleanup_docker_images") {
                sh "docker rmi $IMAGE_SIGNALER:$TAG || true"
                sh "docker rmi $IMAGE_SIGNALER:latest || true"

                sh "docker rmi $IMAGE_GATEWAY:$TAG || true"
                sh "docker rmi $IMAGE_GATEWAY:latest || true"

                sh "docker rmi $IMAGE_ASSISTANT:$TAG || true"
                sh "docker rmi $IMAGE_ASSISTANT:latest || true"

                sh "docker rmi $IMAGE_DIRECTOR:$TAG || true"
                sh "docker rmi $IMAGE_DIRECTOR:latest || true"
            }
        }
    }
}
