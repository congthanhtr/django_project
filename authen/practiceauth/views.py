from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action, permission_classes, authentication_classes
from .serializers import ChangePasswordSerializer, ForgotPasswordSerializer, LoginSerializer, RegisterSerializer
from django.contrib.auth import authenticate
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from rest_framework import generics
# Create your views here.
# Oauth --- login, register, forgot_password
# Refresh Token
# Oauth2
# Swagger
# Redis
# NoSQL
# Docker
# Chatting
# Unit Test


class LoginView(APIView):
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(data = 'Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is None:
            return Response('Invalid Credentials', status=status.HTTP_401_UNAUTHORIZED)
    
        token = RefreshToken().for_user(user=user)
        return Response(data={
            'refresh_token': str(token),
            'access_token': str(token.access_token)
        }, status=status.HTTP_200_OK)


class AuthViewSet(viewsets.ModelViewSet):

    @action(methods=['POST'], detail=False, url_path='login', url_name='login')
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is None:
            return Response('Invalid Credentials', status=status.HTTP_401_UNAUTHORIZED)
    
        token = RefreshToken().for_user(user=user)
        return Response(data={
            'refresh_token': str(token),
            'access_token': str(token.access_token)
        }, status=status.HTTP_200_OK)
    
    @action(methods=['POST'], detail=False, url_path='register', url_name='register')
    def register(self, request):
        form_data = request.data
        serializer = RegisterSerializer(data=form_data)
        if not serializer.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)

        validated_data = serializer.validated_data
        if not validated_data['err']:
            user = User(
                username=validated_data['username'],
                email=validated_data['email']
            )
            user.set_password(validated_data['password'])
            user.save()
            token = RefreshToken.for_user(user)
            return Response({
                'refresh_token': str(token),
                'access_token': str(token.access_token),
                'username': user.username
            })
        else:
            return Response(validated_data['err'], status=status.HTTP_400_BAD_REQUEST)
    
    @action(methods=['POST'], detail=False, url_path='forgot-password', url_name='forgot-password')
    def forgot_password(self, request):
        form_data = request.data
        serializer = ForgotPasswordSerializer(data=form_data)

        if not serializer.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        if 'err' not in validated_data:
            user = self.get_queryset().filter(email=validated_data['email'])
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = reverse("reset-password", kwargs={"id":user.id, "token": token})
            reset_url = f"localhost:8000{reset_url}"
            return Response({
                'message': f'password reset link: {reset_url}'
            }, status=status.HTTP_200_OK)
        else:
            return Response(data=validated_data['err'], status=status.HTTP_400_BAD_REQUEST)
    

class ChangePasswordViewSet(viewsets.ModelViewSet):
    authentication_classes = (JWTAuthentication,)
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated,)
    queryset = User.objects.all()

    @action(methods=['PUT'], detail=False, url_path='change', url_name='change-password')
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if not serializer.is_valid():
            return Response('Bad request', status=status.HTTP_400_BAD_REQUEST)
    
        validated_data = serializer.validated_data
        if 'err' in validated_data:
            return Response(data=validated_data['err'], status=status.HTTP_401_UNAUTHORIZED)

        user = self.request.user
        if user.check_password(validated_data['old_password']):
            user.set_password(validated_data['new_password'])
            user.save()            
            return Response(data={
                'msg': 'Update message sucessfully'
            }, status=status.HTTP_200_OK)
        else:
            return Response(data={
                'msg': 'Wrong old password'
            }, status=status.HTTP_401_UNAUTHORIZED)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()

    @action(methods=['GET'], detail=False, url_path='list', url_name='list')
    def list_user(self, request):
        return Response(data=self.get_queryset(), status=status.HTTP_200_OK)
        # return Response('OK')