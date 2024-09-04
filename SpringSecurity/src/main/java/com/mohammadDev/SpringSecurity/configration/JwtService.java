package com.mohammadDev.SpringSecurity.configration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "0tl3wfgGwNdQXNvlEuhvlUQjMpodDZC8" ;
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }


    public <T> T extractClaim(String token , Function<Claims,T> claimsResolver  ){

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            /*hya5od al extra claims w y7tohom 3l token  */
            Map<String,Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts.builder()
                /*hya5od al claims algdida w y7otaha ll username */
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                /*this token valid for one day */
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                //generate and return the token
                .compact();
    }



    public boolean isTokenValid ( String token , UserDetails userDetails){

        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()))&& !isTokenExpired(token);


    }


    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    /*                .setSigningKey(getSignInKey())
    Sets the signing key used to verify any discovered JWS digital signature.

     */
    private Claims extractAllClaims(String token){
        /*when we want to generate token we need to use the sign in key
         * The signing key is a JSON web key (JWK) that contains a well-known public
         *  key used to validate the signature of a signed JSON web token (JWT).
         * A JSON web key set ( JWKS ) is a set of keys containing the public keys
         *  used to verify any JWT issued by the authorization
         *  server and signed using the RS256 signing algorithm.*/
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }


    //used to create the signature part of the JWT which used to verify the sender
    //who claims to be ensured  that the massage was not change along
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
