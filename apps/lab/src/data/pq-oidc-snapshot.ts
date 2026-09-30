// Snapshot of this project's provider (npm start), captured 2026-09-30.
// Used by the provider check so visitors can compare a post-quantum-capable provider.
export const PQ_OIDC_SNAPSHOT = {
  "discovery": {
    "authorization_endpoint": "http://localhost:3000/auth",
    "claims_parameter_supported": false,
    "claims_supported": [
      "sub",
      "name",
      "given_name",
      "family_name",
      "email",
      "email_verified",
      "sid",
      "auth_time",
      "iss"
    ],
    "code_challenge_methods_supported": [
      "S256"
    ],
    "end_session_endpoint": "http://localhost:3000/session/end",
    "grant_types_supported": [
      "authorization_code",
      "refresh_token"
    ],
    "issuer": "http://localhost:3000",
    "jwks_uri": "http://localhost:3000/jwks",
    "authorization_response_iss_parameter_supported": true,
    "response_modes_supported": [
      "form_post",
      "fragment",
      "query"
    ],
    "response_types_supported": [
      "code"
    ],
    "scopes_supported": [
      "openid",
      "offline_access",
      "profile",
      "email"
    ],
    "subject_types_supported": [
      "public"
    ],
    "token_endpoint_auth_methods_supported": [
      "client_secret_basic",
      "client_secret_jwt",
      "client_secret_post",
      "private_key_jwt",
      "none"
    ],
    "token_endpoint_auth_signing_alg_values_supported": [
      "HS256",
      "RS256",
      "PS256",
      "ES256",
      "Ed25519",
      "EdDSA"
    ],
    "token_endpoint": "http://localhost:3000/token",
    "id_token_signing_alg_values_supported": [
      "ES256",
      "ML-DSA-65"
    ],
    "pushed_authorization_request_endpoint": "http://localhost:3000/request",
    "request_uri_parameter_supported": false,
    "userinfo_endpoint": "http://localhost:3000/me",
    "dpop_signing_alg_values_supported": [
      "ES256",
      "Ed25519",
      "EdDSA"
    ],
    "claim_types_supported": [
      "normal"
    ]
  },
  "jwksText": "{\"keys\":[{\"kty\":\"EC\",\"use\":\"sig\",\"kid\":\"CJGKjvfKdWaDlLf14nPlusWevlef76LcEawZtum2-x0\",\"alg\":\"ES256\",\"crv\":\"P-256\",\"x\":\"UczbkMPdqmqOXNrbr9GNmgl58nYZ2qBR7hkVVxk0cHU\",\"y\":\"nn9ITejFI5b41MjwinFPQY6mNsV3nkCayxn2AN7-vlg\"},{\"kty\":\"AKP\",\"use\":\"sig\",\"kid\":\"Vw4sLgthQp2vsmGCA5Boi2r5Fj1S81t-fwICyy5nG0k\",\"alg\":\"ML-DSA-65\",\"pub\":\"myTTiTvfXmjMEECma8BAi464mbLgCprVk-kyqAj43mVytbx8DT4xr_bqIcPbejcLlGXmrp5wAY505ML1sXhTW2L-9YEvzuRtryqrTgsZCNo_UwdjBwWpTjThzx7RduViuFZ948-66Mblp8qBVNT7gSUsXkTKvHAXUZbP0lcVSrONw1Trd3sCBSIbojIZe77HRv4H4pU_RDDTZ2ivJHUNdGpNR0QGtzVFaJonUZaEzb3abucShuodiPdMJj8Eh3dN6Te1Z8AsWTcwROyV_Aih8wPzx4cxom-hBKezCxkdFVGWRLRPZj3c05J6encx7F7LjwqO-9TvWsAA96lMy505lr2GxIWbQxIw-JW4V6neu13wERWr9-Q0D37g_krQ8b6hzko79sWbba_HM-RNv-CMtYPcp-7jZyykpyDfgoTPfFCi_KtxFDUS8yP2BIBTo5YreYPD9Bji3wBmXbMgwNRT6Akp5rK3PAEpcElIo3DOCYlZNKXfXHjlqsCXvkN8YTtxWxgrmWZQ9NMG14kPEJu3MI82GQqhYfhbnKHX_U4-3xy_9BxQhNrNVNrRpGGRlWKu4ZYGSzO5tnW23ojXzQyqCQOqZ1DzvheE6tqwzn1TUAwUJtwWdk4JgIyYqEhvW9sMZ2iu53E3Rch3Fv96LoN3AnfFKWk643i_hUGSU8O-kZZigCMMePIg7CLqtq_U1RC9h51uYVWBAvgc1pWUiUYBssNqaA8nDAaEAtZLQWgw3JiJ-esZiACCs8ALcQG7wdGm5fOkWFg8e5h8Ez9AxGoeQ2tgDKoqojlyx3DZhIkgkL3U3N5yQwPVc056xXoNiHdaYtbU093a0ibUWUprBg7QMnV546qPjoLwwnbH1Yvo9y75BFtMO3YFfPJMAldWrJPVxHtIEzdsEJnNXeno_ZdnKy0fbR0AgVNVsWYIW-fHZ2de2LUHaG7Rtm4Gid0aMnRTli333AueBHNJCr9QMy6Tk6Fr-gdEU9qFfjD2zgu-M320BfO0sJ8tJzMS9boqDMopYxijGuOHdzMGrMsMzoQIFAclr0LpJSLGCEWKQjyl-4wMdIbaA8HKDF6uonF84bvqEVOYPlajabd-0As_v0ZTyqd8DaQY3hHICnkQPfWKPc4H0oSRTtF-n_z6T-oIaGxrI6AvGNiUAiBhnlTWxr99F3CmyBtE5YY1P_46yihD2By-pUHFFsKFU6HfeRn66zr2ZS8Wm_nTU3xyOL_XwwUEABfQ6aoXXXssQQjcRn5KdSq7_shUJ3mWK9DMTF_fknjReNjqDCZAqhInkcYTF-cTMokaRtOa86fOFdgptiOgduoHEJo1mx65d5qv2uF0UjH001prM0UYxzG7pqyCDnfRJjwEVbWc2cvlOZxx9UG46yWyMzU8jiMSMhT0exNj6rMTsAQDsS0w1Jf1nCUa3fgEG7Q0aHWa1lkcXghUks6zQp7hn5ArEMPANfL6CYqg4NFVKGs7SBlED5YT2floPkbhv2LRAH5Mdd6FM_Y6zNUGXnZrNuWjCeQPbANpqh-SqfrVusvUMcejYcSl2L3sAqK1S09Fq7DYESs5hLn5tZBjxOPQ3WntR1M0my8YG43k12WEVZb5CTq2rJ1aL2VootRdPa7h1uiAwMkWVd2wUtD8zB7TITsqFtttY3-j3O7kCkbOK09yw1rAfuy7-w5ebGF9GBtDzAF0BlxW4NI28OQaRmJZmbmLFdIfKrg0r0eVKBuyA7DapAGjo9cbGsHK_hIcOpEMP8GaPfGBlhyx_YTKQQglhy2MeBh9JuAucS2NyDmRXxxqbUg5Y6MUOXI5Y-1O29SZLgf5_ZS0DcdoWnS2o9s84i3b1vys94bUKbO4IQgonN-fN_w-rECkU8TbygOLUStx6Y1CDNBNqCgeNhx_VEdFPb7_mtIOYuLZDXoYO32_RtKfKl0sEvT39PicTmyhgNR0waAMf_y4iINHteIv8unUKRyf-v39_gCQ_8_w7tGhqDuKVWWL35CqvDQ9VD6EZh-PR3zI9fsNAWIdN-PpAf7uuig59O_2pruCpl2QYIgASeJS_GToOPhpZAEzWwKnpJT3W3fe5Af_SopH94XTGPtdWj3fDZui8gxN4oX7-J7Nejs7ZCwpY2DnwcxZvnrsiSUOZ1TNiGHdfTfbxVtWR1KsGbvwj4d5KrJ34XmCTvuWawH7BDzN2D5o4wA_8ewt-2OcKt7LZudEtwZFTtNohnQ-u1MxtC5qeAkO4_XZSV4C3BkoOFOKEjTQ44odPSDqmojhi-qP9iZTBTjHJnDMBsjiSvVOaUjIXsbMSSVEVa_49m2GdwW1eTJ7gP98F-BrcQaR7bsg3qdMa37NgEVGftrXVGnx1VGs0byWW1Gg4YP7i0oSqjTrG7hK4DffBjX2PL0ul6-eC9yVyhgq5kaEEOsGKNa_sccIt1HFTrkx80qdneWPSc_I9TEzG7CRRG9ET__OD5MBHy_NmOwN_lWMRDdy5J2MsbiEnZEYmAXzZNVN7I-SuIE3WKIMGY-2lzV6oPCDWWp_lSBfvo_emOtebKI-7IH3Au-K6nplu3qwJ5tgA_6B8f1ptXGw7KKYRowG2Qs7k1bgfy5nCKU8BAT7n2I\"}]}"
};
