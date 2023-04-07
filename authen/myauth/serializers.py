from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import serializers

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)
        return data
    

class ExampleSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    age = serializers.IntegerField()
