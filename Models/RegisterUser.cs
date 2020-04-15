using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Login_Reg.Models
{
    public class RegisterUser
    {
        [Key]
        public int UserId {get;set;}
        [Required(ErrorMessage="You must enter a first name")]
        [MinLength(2, ErrorMessage="This name must be at least 2 characters long.")]
        public string FirstName {get; set;}

        [Required(ErrorMessage="You must enter a last name")]
        [MinLength(2, ErrorMessage="This name must be at least 2 characters long.")]
        public string LastName {get; set;}
        [Required(ErrorMessage="You must enter an email.")]
        [DataType(DataType.EmailAddress)]
        [EmailAddress]
        public string Email {get; set;}
        [Required(ErrorMessage="You must enter an password.")]
        [DataType(DataType.Password)]
        [MinLength(8, ErrorMessage="This password must be at least 8 characters long.")]
        public string Password {get; set;}
        public DateTime CreatedAt {get;set;} = DateTime.Now;
        public DateTime UpdatedAt {get;set;} = DateTime.Now;

        [NotMapped]
        [Compare("Password",ErrorMessage="Confirm password did not match, please try again.")]
        [DataType(DataType.Password)]

        public string ConfirmPassword {get; set;}

    }
}