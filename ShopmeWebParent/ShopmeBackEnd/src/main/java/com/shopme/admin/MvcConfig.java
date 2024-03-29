package com.shopme.admin;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class MvcConfig implements WebMvcConfigurer {

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        String dirName = "ShopmeWebParent/ShopmeBackEnd/user-photos";
        Path userPhotosDir = Paths.get(dirName);

        String userPhotosPath = userPhotosDir.toFile().getAbsolutePath();

        registry.addResourceHandler("/" + dirName + "/**")
                .addResourceLocations("file:/" + userPhotosPath + "/");

        String categoryImagesDirName = "ShopmeWebParent/ShopmeBackEnd/category-images";
        Path categoryImagesDir = Paths.get(categoryImagesDirName);

        String categoryImagesPath = categoryImagesDir.toFile().getAbsolutePath();

        registry.addResourceHandler("/" + categoryImagesDirName + "/**")
                .addResourceLocations("file:/" + categoryImagesPath + "/");

        String brandLogoDirName = "ShopmeWebParent/ShopmeBackEnd/brand-logos";
        Path brandLogoDir = Paths.get(brandLogoDirName);

        String brandLogoPath = brandLogoDir.toFile().getAbsolutePath();

        registry.addResourceHandler("/" + brandLogoDirName + "/**")
                .addResourceLocations("file:/" + brandLogoPath + "/");

    }
}
