from rest_framework import serializers
from django.contrib.auth.models import User

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()


class RegisterSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()