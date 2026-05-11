package main

import future.keywords.in

_valid := {
	"kind": "Deployment",
	"spec": {"template": {"spec": {"containers": [{
		"name": "app",
		"image": "us-central1-docker.pkg.dev/project/platform/app:abc123def456",
		"resources": {
			"requests": {"cpu": "100m", "memory": "64Mi"},
			"limits": {"cpu": "200m", "memory": "128Mi"},
		},
		"securityContext": {
			"runAsNonRoot": true,
			"readOnlyRootFilesystem": true,
		},
	}]}}}
}

test_valid_deployment_passes {
	count(deny) == 0 with input as _valid
}

test_non_deployment_ignored {
	count(deny) == 0 with input as {"kind": "Service", "spec": {}}
}

test_deny_latest_tag {
	bad := json.patch(_valid, [{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "myapp:latest"}])
	some msg in deny with input as bad
	contains(msg, ":latest")
}

test_deny_missing_cpu_request {
	bad := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{
			"name": "app", "image": "myapp:abc123",
			"resources": {"requests": {"memory": "64Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
			"securityContext": {"runAsNonRoot": true, "readOnlyRootFilesystem": true},
		}]}}},
	}
	some msg in deny with input as bad
	contains(msg, "requests.cpu")
}

test_deny_missing_memory_request {
	bad := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{
			"name": "app", "image": "myapp:abc123",
			"resources": {"requests": {"cpu": "100m"}, "limits": {"cpu": "200m", "memory": "128Mi"}},
			"securityContext": {"runAsNonRoot": true, "readOnlyRootFilesystem": true},
		}]}}},
	}
	some msg in deny with input as bad
	contains(msg, "requests.memory")
}

test_deny_missing_cpu_limit {
	bad := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{
			"name": "app", "image": "myapp:abc123",
			"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}},
			"securityContext": {"runAsNonRoot": true, "readOnlyRootFilesystem": true},
		}]}}},
	}
	some msg in deny with input as bad
	contains(msg, "limits.cpu")
}

test_deny_missing_memory_limit {
	bad := {
		"kind": "Deployment",
		"spec": {"template": {"spec": {"containers": [{
			"name": "app", "image": "myapp:abc123",
			"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"cpu": "200m"}},
			"securityContext": {"runAsNonRoot": true, "readOnlyRootFilesystem": true},
		}]}}},
	}
	some msg in deny with input as bad
	contains(msg, "limits.memory")
}

test_deny_running_as_root {
	bad := json.patch(_valid, [{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot", "value": false}])
	some msg in deny with input as bad
	contains(msg, "runAsNonRoot")
}

test_deny_writable_rootfs {
	bad := json.patch(_valid, [{"op": "replace", "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem", "value": false}])
	some msg in deny with input as bad
	contains(msg, "readOnlyRootFilesystem")
}

test_deny_privileged {
	bad := json.patch(_valid, [{"op": "add", "path": "/spec/template/spec/containers/0/securityContext/privileged", "value": true}])
	some msg in deny with input as bad
	contains(msg, "privileged")
}
