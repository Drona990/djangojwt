from django.shortcuts import render
from rest_framework import generics,views
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .serializer import RegisterSerializer ,LoginSerializer,UserSerializer
from rest_framework.response import Response
from rest_framework.decorators import api_view,permission_classes
from rest_framework_simplejwt.tokens import RefreshToken


#Function based API
@api_view(['GET'])
@permission_classes([AllowAny])
def test_view(request):
    return Response({"message": "Hello from function-based API!"})

class TestView(views.APIView):
    permission_classes = [AllowAny]
    def get(self , request, *args , **kwargs):
        return Response({
            "message": "Hello World"

        })

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request , *args , **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username,password=password)
        if user is not None:
            refreshToken = RefreshToken.for_user(user)
            userSerializer = UserSerializer(user).data
            return Response({
                'status':"Success",
                'refreshToken':str(refreshToken),
                'accessToken':str(refreshToken.access_token),
                'user':userSerializer
            })
        else:
            return Response({
                'status':"Failed",
                "message":"Invalid credential",
            },status=401)

class ProtectedView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        return Response({
            "message":"Welcock to protectedView"
        })

