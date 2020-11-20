from django.conf.urls import url

from panacea import views

app_name = 'panacea'

urlpatterns = [
    # ex: /polls/
    url(r'^$', views.index, name='index'),
    # ex: /polls/5/
    # url(r'^(?P<question_id>[0-9]+)/$', views.detail, name='detail'),
    # ex: /polls/5/results/
    # url(r'^(?P<question_id>[0-9]+)/results/$', views.results, name='results'),
    # ex: /polls/5/vote/
    # url(r'^(?P<question_id>[0-9]+)/vote/$', views.vote, name='vote')
    url(r'^active-investigation/$', views.active_investigation, name='active_invst'),
    url(r'^upload-email-header-for-training/$', views.email_header_training, name='training'),
    url(r'^upload-email-header-for-testing/$', views.email_header_testing, name='testing'),
    url(r'^test-rakeb/$', views.email_header_testing, name='test_rakeb'),
    url(r'^health/$', views.health_dashboard, name='health_dashboard'),
    # url(r'^test-rakeb/$', views.test_rakeb, name='test_rakeb'),
]