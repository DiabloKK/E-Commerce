package com.shopme.admin.user;

import com.shopme.common.entity.Role;
import com.shopme.common.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.annotation.Rollback;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Rollback(value = false)
public class UserRepositoryTests {

    @Autowired
    private UserRepository repo;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    public void testCreateNewUserWithOneRole() {
        Role roleAdmin = entityManager.find(Role.class, 1);
        User userKhang = new User("khang@gmail.com", "khang123456", "Vo", "Khang");
        userKhang.addRole(roleAdmin);

        User saveUser = repo.save(userKhang);
        assertThat(saveUser.getId()).isGreaterThan(0);
    }

    @Test
    public void testCreateNewUserWithTwoRoles() {
        User userRavi = new User("ravi@gmail.com", "ravi2030", "Ravi", "Kumar");
        Role roleEditor = new Role(3);
        Role roleAssistant = new Role(5);

        userRavi.addRole(roleEditor);
        userRavi.addRole(roleAssistant);

        User saveUser = repo.save(userRavi);

        assertThat(saveUser.getId()).isGreaterThan(0);
    }

    @Test
    public void testListAllUsers() {
        Iterable<User> listUsers = repo.findAll();
        listUsers.forEach(user -> {
            System.out.println(user);
        });
    }

    @Test
    public void testGetUserById() {
        User userKhang = repo.findById(1).get();
        System.out.println(userKhang);
        assertThat(userKhang).isNotNull();
    }

    @Test
    public void testUpdateUserDetails() {
        User userKhang = repo.findById(1).get();
        userKhang.setEnabled(true);
        userKhang.setEmail("vokhuong1403@gmail.com");

        repo.save(userKhang);
    }

    @Test
    public void testUpdateUserRoles() {
        User userRavi = repo.findById(2).get();
        Role roleEditor = new Role(3);
        Role roleSalesperson = new Role(2);

        userRavi.getRoles().remove(roleEditor);
        userRavi.addRole(roleSalesperson);

        repo.save(userRavi);
    }

    @Test
    public void testDeleteUser() {
        Integer userId = 2;
        repo.deleteById(userId);
    }

    @Test
    public void testGetUserByEmail() {
        String email = "ravi@gmail.com";
        User user = repo.getUserByEmail(email);

        assertThat(user).isNotNull();
    }

}
