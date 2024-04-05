package com.burakkutbay.springsecurityjwtexample.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Builder
public class ChangePasswordRequest {


    private  String currentPassword;
    private  String newPassword;
    private  String confirmationPassword;

}
