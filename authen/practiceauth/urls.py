from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import LoginView, AuthViewSet, UserViewSet, ChangePasswordViewSet
from rest_framework import routers  


urlpatterns = [
    # above is my testing
    path('auth/login/', LoginView.as_view())
]

router = routers.SimpleRouter(trailing_slash=False)
router.register(r'v1/auth', AuthViewSet, basename='auth')
router.register(r'v1/users', UserViewSet, basename='user')
router.register(r'v1/password', ChangePasswordViewSet, basename='change-password')

urlpatterns += router.urls