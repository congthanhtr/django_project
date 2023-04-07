from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
# Create your views here.

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

