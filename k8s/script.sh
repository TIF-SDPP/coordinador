#!/bin/bash

# Script para aplicar el deployment de Coordinador en Kubernetes

# Aplicar el archivo de configuración de Kubernetes
kubectl apply -f ./deploy-coordinador.yaml

# Aplicar el archivo de configuración de Kubernetes
kubectl apply -f ./service-coordinador.yaml