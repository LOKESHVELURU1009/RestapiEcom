from django.urls import path
from app.views import *

urlpatterns = [
    path('register/', register, name='register'),
    path('login/', login, name='login'),
    path('update/<int:pk>/', update, name='update'),
    path('change_password/',change_password,name='change_password'),
    path('add_product/', add_product, name='add_product'),
    path('product_list/',product_list,name='product_list'),
    path('update_product/<int:pk>/', update_product, name='update-product'),
    path('delete_product/<int:pk>/', delete_product, name='delete-product'),
    path('add_to_wishlist/', add_to_wishlist, name='add_to_wishlist'),
    path('remove_from_wishlist/<int:wishlist_id>/', remove_from_wishlist, name='remove_from_wishlist'),
    path('add_to_cart/', add_to_cart, name='add_to_cart'),
    path('remove_from_cart/<int:cart_id>/', remove_from_cart, name='remove_from_cart'),
    path('categories/', category_list, name='category-list'),
    path('categories/<int:pk>/', category_detail, name='category-detail'),
    path('change_role/<int:user_id>/', change_role, name='change_role'),


]