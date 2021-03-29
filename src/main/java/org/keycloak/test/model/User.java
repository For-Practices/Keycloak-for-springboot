package org.keycloak.test.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.apachecommons.CommonsLog;

import javax.persistence.*;

@Entity
@Table(name = "user")
@Data
@AllArgsConstructor @NoArgsConstructor @ToString
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(name = "user_name")
    private String name;
    @Column(name = "user_password")
    private String password;
}
