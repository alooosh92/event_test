using System.ComponentModel.DataAnnotations;

namespace event_test.VModels
{
    public class VMEventBooking
    {
        [Required] public string? Username { get;set; }
        [Required] public int NumTicket { get; set; }
    }
}
