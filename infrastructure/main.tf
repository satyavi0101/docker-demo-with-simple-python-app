terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "The AWS region to deploy resources in"
  type        = string
  default     = "us-east-1"
}

variable "app_name" {
  description = "Application name for resource naming"
  type        = string
  default     = "my-web-app"
}

variable "docker_source_repo" {
  description = "GitHub repository URL containing Dockerfile and source code"
  type        = string
  default     = "https://github.com/satyavi0101/docker-demo-with-simple-python-app.git"
}

# Use default VPC and subnets
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Create ECR repository to store Docker image
resource "aws_ecr_repository" "app_repo" {
  name = var.app_name
  image_scanning_configuration {
    scan_on_push = true
  }
  tags = {
    Name = var.app_name
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "app_cluster" {
  name = "${var.app_name}-cluster"
}

# IAM role for ECS task execution
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.app_name}-ecs-task-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Security group for ECS tasks allowing inbound HTTP traffic from anywhere
resource "aws_security_group" "ecs_sg" {
  name        = "${var.app_name}-ecs-sg"
  description = "Allow inbound HTTP traffic to ECS tasks"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "Allow HTTP inbound"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-ecs-sg"
  }
}

# ECS Task definition with Fargate launch type
resource "aws_ecs_task_definition" "app_task" {
  family                   = var.app_name
  cpu                      = "256"
  memory                   = "512"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = var.app_name
      image     = "${aws_ecr_repository.app_repo.repository_url}:latest"
      portMappings = [
        {
          containerPort = 80
          protocol      = "tcp"
        }
      ]
      essential = true
    }
  ])
}

# ECS Service with public IP and no load balancer
resource "aws_ecs_service" "app_service" {
  name            = "${var.app_name}-service"
  cluster         = aws_ecs_cluster.app_cluster.id
  task_definition = aws_ecs_task_definition.app_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = data.aws_subnets.default.ids
    security_groups = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }
}

# Null resource to clone repo, build Docker image, login and push to ECR
resource "null_resource" "docker_build_push" {
  depends_on = [aws_ecr_repository.app_repo]

  provisioner "local-exec" {
    command = <<EOT
    set -e

    # Temp directory for cloning repo
    TMP_DIR=$(mktemp -d)

    echo "Cloning repository ${var.docker_source_repo} into $TMP_DIR"
    git clone ${var.docker_source_repo} $TMP_DIR

    cd $TMP_DIR

    # Get ECR login password and login docker
    aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${aws_ecr_repository.app_repo.repository_url}

    # Build docker image with ECR repo URL tag
    docker build -t ${aws_ecr_repository.app_repo.repository_url}:latest .

    # Push to ECR
    docker push ${aws_ecr_repository.app_repo.repository_url}:latest

    # Cleanup
    rm -rf $TMP_DIR
    EOT
    interpreter = ["/bin/bash", "-c"]
  }
}

output "ecr_repository_url" {
  description = "ECR repository URL, use this to tag and push Docker image"
  value       = aws_ecr_repository.app_repo.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.app_cluster.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.app_service.name
}

output "task_definition_family" {
  description = "ECS task definition family"
  value       = aws_ecs_task_definition.app_task.family
}
