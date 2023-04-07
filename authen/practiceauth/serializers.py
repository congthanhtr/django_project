from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.exceptions import ValidationError

all_users = User.objects.all()

class LoginSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()


class RegisterSerializer(serializers.Serializer):

    username = serializers.CharField()
    password = serializers.CharField()
    email = serializers.CharField()

    def validate(self, attrs):
        all_users = User.objects.all()

        username = attrs.get('username')
        password = attrs.get('password')
        email = attrs.get('email')

        if all_users.filter(username=username):
            attrs['err'] = 'User name existed'
            return attrs
        
        if all_users.filter(email=email):
            attrs['err'] = 'Email existed'
            return attrs
        
        return attrs
    

class ChangePasswordSerializer(serializers.ModelSerializer):

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('old_password', 'new_password')

    def validate(self, attrs):
        return attrs

    def update(self, instance, validated_data):
        if instance.check_password(validated_data['old_password']):
            instance.set_password(validated_data['new_password'])
            instance.save()
            return instance
        else:
            raise ValidationError('wrong old password')

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.CharField()

    def validate(self, attrs):
        if 'email' in attrs:
            if not all_users.filter(email=attrs['email']):
                attrs['err'] = 'No email existed'
                return attrs
        return attrs

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'id')
