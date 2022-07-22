# Authentication Kairnial Module for Python

This module contains authentication classes that were initialy developed for dynamics-apis-v3 and that are now in a separate repository to allow inclusion into other applications

# Module

The module is called kl_authentication

# Submodules 

## authentication
Verify access token
Extract user information from access_token

## decorators
handle authentication web service errors

## middlewares
Get username from payload
Set user_id and token attributes on request object

## openapi
Token Scheme for OpenApi 3 and Swagger interface

## serializers / views / services 
Token generation from Kairnial Auth backend