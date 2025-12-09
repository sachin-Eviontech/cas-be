from django.db import models

# Create your models here.
class Organization(models.Model):
    class Meta:
        db_table = "organization"

    name = models.CharField(max_length=255,unique=True)
    logo = models.ImageField(upload_to="organizations-logo")
    message = models.CharField(max_length=255, null=True, blank=True)
    package_name = models.CharField(max_length=255, null=True, blank=True)
    show_warning = models.BooleanField(default=False)
    block_access = models.BooleanField(default=False)

    def __str__(self):
        return self.name
