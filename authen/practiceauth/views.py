import datetime
import json
import os
from django.conf import settings
from django.shortcuts import render
import redis
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action, permission_classes, authentication_classes
from .serializers import ChangePasswordSerializer, ForgotPasswordRequestSerializer, ForgotPasswordResetSerializer, LoginSerializer, RegisterSerializer, UserSerializer
from django.contrib.auth import authenticate
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.core.paginator import Paginator
# Create your views here.
# Oauth --- login, register, forgot_password (change password, reset password(?))
# Pagination ---
# Mail Service
# Authorization
# Refresh Token
# Oauth2
# Swagger
# Redis
# NoSQL ---
# Docker
# Chatting
# Unit Test
# DB indexing

redis_instance = redis.StrictRedis(host=settings.REDIS_HOST,
                                  port=settings.REDIS_PORT, db=0)

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

    queryset=User.objects.all()

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
        user.last_login = datetime.now()
        user.save()
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
        
    @action(methods=['POST'], detail=False, url_name='forgot-password-request', url_path='forgot-password-request')
    def forgor_password_request(self, request):
        form_data = request.data
        serializer = ForgotPasswordRequestSerializer(data=form_data)

        if not serializer.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        if 'err' in serializer.validated_data:
            return Response(data=serializer.validated_data['err'], status=status.HTTP_400_BAD_REQUEST)
        
        user = self.get_queryset().get(email=serializer.validated_data['email'])
        token = PasswordResetTokenGenerator().make_token(user)
        
        reset_url = f"{settings.DOMAIN_NAME}/forgot-password-reset/{user.id}/{token}"
        return Response({
            'message': f'password reset link: {reset_url}'
        }, status=status.HTTP_200_OK)
    
    @action(methods=['POST'], detail=False, url_path=r'forgot-password-reset', url_name='forgot-password-reset')
    def forgot_password(self, request):
        form_data = request.data
        serializer = ForgotPasswordResetSerializer(data=form_data)

        if not serializer.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        validated_data = serializer.validated_data
        if 'err' not in validated_data:
            user = self.get_queryset().get(id=validated_data['id'])
            user.set_password(validated_data['new_password'])
            user.save()
            return Response({
                'message': f'password has been reseted'
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
    model = User
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    @action(methods=['GET'], detail=False, url_path='list', url_name='list')
    def list_user(self, request):
        page = int(request.GET.get('page', '1'))
        per_page = int(request.GET.get('perPage', '2'))
        list_user = None
        if redis_instance.get('list_user'):
            list_user = redis_instance.get('list_user')
        else:
            list_user = self.get_serializer(self.get_queryset(), many=True).data
            
        paginator = Paginator(list_user, per_page=per_page)
        return Response(data={
            'data': paginator.page(page).object_list,
            'current_page': page,
            'total_page': paginator.num_pages,
            'per_page': per_page
        })

from django.core.mail import EmailMultiAlternatives, get_connection       
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.template import Context
from django.template.loader import render_to_string
from django.utils.html import strip_tags

@csrf_exempt
def send_email(request):
    if request.method == "POST":
        body = json.loads(request.body)
        subject = body.get("subject")
        email_from = settings.EMAIL_HOST_USER
        recipient_list = body.get("email")
        message = body.get("message")
        html_content = render_to_string('simple_mail.html', context={'messages': message})
        print(html_content)
        text_content = strip_tags(html_content)
        msg = EmailMultiAlternatives(subject=subject,body=text_content,from_email=email_from,to=recipient_list)
        msg.attach_alternative(html_content, 'text/html')
        msg.send()
         
    return Response("OK")
