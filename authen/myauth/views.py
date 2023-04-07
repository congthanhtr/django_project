from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response 
from .serializers import MyTokenObtainPairSerializer, ExampleSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework import status
# Create your views here.

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

class TestAPIView(APIView):
    pass

class TestSerializerView(APIView):
    serializer_class = ExampleSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request):
        data = ExampleSerializer(data=request.data)
        if not data.is_valid():
            return Response('Bad Request', status=status.HTTP_400_BAD_REQUEST)
        
        return Response(data.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([JWTAuthentication])
def get_example(request):
    return Response('OK')

# above is my testing