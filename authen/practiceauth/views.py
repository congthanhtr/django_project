from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .serializers import LoginSerializer
# Create your views here.

class LoginView(APIView):
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(data = 'Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        
        return Response(data='Unauthorized', status=status.HTTP_401_UNAUTHORIZED)