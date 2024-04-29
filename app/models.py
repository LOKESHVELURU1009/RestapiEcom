from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    dealer_details = models.CharField(max_length=100, blank=True, null=True)
    admin_details = models.CharField(max_length=100, blank=True, null=True)

    class Role(models.TextChoices):
        USER = 'user', 'User'
        DEALER = 'dealer', 'Dealer'
        ADMIN = 'admin', 'Admin'  

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER)

    def __str__(self):
        return self.username
    
class Category(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    is_visible = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='children')

    def __str__(self):
        return self.name


class Product(models.Model):
    dealer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, blank=True, null=True, related_name='products')
    name = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    availability = models.BooleanField(default=True)
    variant = models.JSONField(null=True, blank=True)


    def __str__(self):
        return self.name

class Wishlist(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    time_stamp = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    is_private = models.BooleanField(default=False)
    variant = models.JSONField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'product')


class Cart(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    time_stamp = models.DateTimeField(auto_now_add=True)
    variant = models.JSONField(null=True, blank=True)
    is_private = models.BooleanField(default=False)
    status_choices = [
        ('active', 'Active'),
        ('purchased', 'Purchased'),
        ('removed', 'Removed'),
    ]
    status = models.CharField(max_length=20, choices=status_choices, default='active')

    def __str__(self):
        return f"{self.user.username}'s Cart Item"
    
