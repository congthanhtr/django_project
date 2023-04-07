from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import TestAPIView, CustomTokenObtainPairView, get_example, TestSerializerView


urlpatterns = [
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('info/', get_example, name='info'),
    path('example_serializers/', TestSerializerView.as_view())
    # above is my testing
]