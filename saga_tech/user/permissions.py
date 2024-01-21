from rest_framework.permissions import BasePermission


class IsOwnerOrReadOnly(BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Assumes the model instance has a `user` attribute.
    """

    def has_object_permission(self, request, view, obj):
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True

        return obj.user == request.user


class IsAdminUser(BasePermission):

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            # Check if the user has the 'admin' role
            return 'Admin' == request.user.role

        return False
