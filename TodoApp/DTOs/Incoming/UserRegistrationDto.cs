using System.ComponentModel.DataAnnotations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TodoApp.DTOs.Incoming
{
    public class UserRegistrationDto

    {
        [Required]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}