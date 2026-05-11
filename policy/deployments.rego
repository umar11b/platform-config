package main

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	endswith(container.image, ":latest")
	msg := sprintf("container '%s': image uses ':latest' tag — pin to a specific digest or tag", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.requests.cpu
	msg := sprintf("container '%s': missing resources.requests.cpu", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.requests.memory
	msg := sprintf("container '%s': missing resources.requests.memory", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.limits.cpu
	msg := sprintf("container '%s': missing resources.limits.cpu", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.resources.limits.memory
	msg := sprintf("container '%s': missing resources.limits.memory", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.runAsNonRoot == true
	msg := sprintf("container '%s': runAsNonRoot must be true", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	not container.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("container '%s': readOnlyRootFilesystem must be true", [container.name])
}

deny[msg] {
	input.kind == "Deployment"
	container := input.spec.template.spec.containers[_]
	container.securityContext.privileged == true
	msg := sprintf("container '%s': privileged containers are not allowed", [container.name])
}
