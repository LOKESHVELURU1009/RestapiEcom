from rest_framework import serializers
from app.models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            role=validated_data['role']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name' , 'role']
        read_only_fields = ['id', 'username', 'email']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['id', 'dealer', 'name', 'category', 'description', 'price', 'availability', 'variant']
        read_only_fields = ['id']

class WishlistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wishlist
        fields = ['user', 'product', 'time_stamp','last_modified', 'is_private', 'variant']
        read_only_fields = [ 'time_stamp', 'is_private', 'lastmodified']

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cart
        fields = ['user', 'product', 'quantity', 'time_stamp', 'variant', 'is_private', 'status']
        read_only_fields = ['user', 'time_stamp', 'is_private']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'description', 'is_visible', 'created_at', 'updated_at', 'parent']
        read_only_fields = ['id', 'created_at', 'updated_at' 'is_visible']


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'role', 'dealer_details', 'admin_details']
