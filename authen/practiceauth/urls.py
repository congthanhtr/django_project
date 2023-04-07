from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import LoginView


urlpatterns = [
    # above is my testing
    path('auth/login/', LoginView.as_view())
]