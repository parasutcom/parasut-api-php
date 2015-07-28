<?php
  require('oauth2/Client.php');
  require("oauth2/GrantType/IGrantType.php");
  require("oauth2/GrantType/AuthorizationCode.php");
  require("oauth2/GrantType/RefreshToken.php");

  const CLIENT_ID              = 'CLIENT_ID';
  const CLIENT_SECRET          = 'CLIENT_SECRET';
  const REDIRECT_URI           = 'REDIRECT_URI';
  const AUTHORIZATION_ENDPOINT = 'https://www.parasut.com/oauth/authorize';
  const TOKEN_ENDPOINT         = 'https://www.parasut.com/oauth/token';
  $client = new OAuth2\Client(CLIENT_ID, CLIENT_SECRET);

  if (!isset($_GET['code']))
  {
    // authentication call
    $auth_url = $client->getAuthenticationUrl(AUTHORIZATION_ENDPOINT, REDIRECT_URI);
    header('Location: ' . $auth_url);
    die('Redirect');
  }
  else
  {
    // access token request
    $params = array('code' => $_GET['code'], 'redirect_uri' => REDIRECT_URI);
    $response = $client->getAccessToken(TOKEN_ENDPOINT, 'authorization_code', $params);
    // CAUTION! instead of parse_str, assign response directly to $info or find an alternative way.
    // parse_str($response['result'], $info);
    $info = $response['result'];
    $accessToken  = $info['access_token'];
    $refreshToken = $info['refresh_token'];
    print_r($info);
    echo "<br /><br /><br />";

    // set access token for further api calls
    $client->setAccessToken($accessToken);

    // example api call
    $response = $client->fetch('https://www.parasut.com/api/v1/me');
    var_dump($response, $response['result']);
    echo "<br /><br /><br />";

    // in the case of token expiration, use method below
    $params = array('refresh_token' => $refreshToken);
    $response = $client->getAccessToken(TOKEN_ENDPOINT, 'refresh_token', $params);
    $info = $response['result'];
    print_r($info);
    $client->setAccessToken($info['access_token']);
    $response = $client->fetch('https://www.parasut.com/api/v1/33/sales_invoices');
    var_dump($response, $response['result']);
  }
  die;
