package com.ldp.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Controller;

/**
 * @author Return
 * @create 2019-05-29 11:54
 */
@EnableWebSecurity  //自动开启web安全
@Configuration
public class MySercurityConfig extends WebSecurityConfigurerAdapter {

    //认证的方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //认证信息，一般情况他是从数据库中获取的用户名和密码以及该用户所拥有的角色
        auth.inMemoryAuthentication()
                .withUser("admin").password("admin").roles("VIP1","VIP2","VIP3")
                .and()
                .withUser("zhangsan").password("123456").roles("VIP2","VIP3")
                .and()
                .withUser("ldp").password("971018").roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password("123456").roles("VIP1","VIP3")
                .and();

    }

    //授权的方法
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //放行欢迎页面，一般的情况，还需要将静态资源释放
        //定制授权的请求规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启登录功能，即当你登录时自动跳转登录页面，进行认证处理，然后判断是否拥有该角色的权限，
        // 如果没有那么将抛出异常信息Access Denied(拒绝访问)
        //自动登录规则：
        //1、/login 到达登入页面
        //2、重定向到/login?error 表示登录失败
        // http.formLogin();

        http.formLogin().usernameParameter("uname").passwordParameter("upass").loginPage("/userlogin");
        //如果需要跳转到自己定义的登录页面，那么需要注意：
        //1、指定好的登录的用户名以及密码
        //2、指定登录请求的路径
        //3、默认的是post请求 /login表示登录处理
        //4、一旦指定了loginpage 那么loginpage就是post的请求路径

        //开启自动配置的注销功能
        http.logout().logoutSuccessUrl("/");  //表示退出之后的重定向到“/”请求
        //1、访问logout 表示用户注销，清除session值
        //2、注销成功会返回 /login?logout页面 （当然可以自己指定跳转的页面）

        //开启记住我
        http.rememberMe().rememberMeParameter("remenber");
        //1、登录成功之后，将cookie发给浏览器保存，以后访问页面都带上这个cookie，只要通过检查就可以达到免登陆的效果
        //2、点击注销，那么浏览器会自动销毁cookie，（默认的保存的时间是14天）

    }
}
