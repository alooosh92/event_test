using event_test.Models;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace event_test.VModels
{
    public class VMBooking
    {
        [Required] public Guid? Event { get; set; }
        [Required] public int NumTicket { get; set; }
    }
}
