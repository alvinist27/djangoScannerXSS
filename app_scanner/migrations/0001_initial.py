# Generated by Django 4.2 on 2023-04-19 10:24

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='Email')),
                ('date_create', models.DateTimeField(auto_now_add=True, verbose_name='Date create')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'User',
                'verbose_name_plural': 'Users',
            },
        ),
        migrations.CreateModel(
            name='Payload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('body', models.TextField(verbose_name='Body')),
                ('recommendation', models.TextField(blank=True, verbose_name='Recommendation')),
            ],
            options={
                'verbose_name': 'Payload',
                'verbose_name_plural': 'Payloads',
            },
        ),
        migrations.CreateModel(
            name='ScanResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('risk_level', models.CharField(choices=[('A', 'Healthy'), ('B', 'Low'), ('C', 'Medium'), ('D', 'High')], max_length=1, verbose_name='Risk level')),
                ('review', models.JSONField(verbose_name='Review')),
                ('review_file_path', models.FilePathField(path='/home/alvin/projects/djangoScannerXSS/media/reviews', verbose_name='Review')),
            ],
            options={
                'verbose_name': 'Scan result',
                'verbose_name_plural': 'Scan results',
            },
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target_url', models.URLField(max_length=512, verbose_name='Target url')),
                ('xss_type', models.CharField(choices=[('R', 'Reflected'), ('S', 'Stored'), ('D', 'DOM-based'), ('F', 'Full scan')], verbose_name='XSS type')),
                ('date_start', models.DateTimeField(auto_now_add=True, verbose_name='Date start')),
                ('date_end', models.DateTimeField(blank=True, null=True, verbose_name='Date end')),
                ('status', models.IntegerField(choices=[('S', 'Started'), ('E', 'Error'), ('C', 'Completed')], verbose_name='Status')),
                ('result', models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, to='app_scanner.scanresult', verbose_name='Result')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_scans', to=settings.AUTH_USER_MODEL, verbose_name='User')),
            ],
            options={
                'verbose_name': 'Scan',
                'verbose_name_plural': 'Scans',
            },
        ),
    ]