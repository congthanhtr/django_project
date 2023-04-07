from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if authenticate(username, password):
            return attrs
        else:
            return {'msg': 'invalid credentials'}
