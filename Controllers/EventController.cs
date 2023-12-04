using event_test.Data;
using event_test.Models;
using event_test.VModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace event_test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EventController : ControllerBase
    {
        public EventController(UserManager<IdentityUser> userManager,IRepositoryEvent repository)
        {
            UserManager = userManager;
            Repository = repository;
        }

        public UserManager<IdentityUser> UserManager { get; }
        public IRepositoryEvent Repository { get; }

        [HttpGet]
        [Route("Get")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<ActionResult<VMShowEvent?>?> Get(Guid id)
        {
            try
            {
                var lang = "";
                try { lang = Request.GetTypedHeaders().AcceptLanguage[0].ToString(); }
                catch { lang = "ar"; }
                var user = UserManager.GetUserId(User);
                if (user != null)
                {
                    var item = await Repository.Show(user, id);  
                    if (item == null) { return null; }
                    return new VMShowEvent
                    {
                        Description = lang == "en" ? item.EnDescription : item.ArDescription,
                        Location = lang == "en" ? item.EnLocation : item.ArLocation,
                        Name = lang == "en" ? item.EnName : item.ArName,
                        Late = item.Late,
                        Long = item.Long,
                        EventDate = item.EventDate,
                        EventTicket = item.EventTicket
                    };
                }
                return null;
            }
            catch { throw; }
        }
        [HttpGet]
        [Route("GetAll")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<ActionResult<List<VMShowEvent>?>?> GetAll()
        {
            try
            {
                var lang = "";
                try { lang = Request.GetTypedHeaders().AcceptLanguage[0].ToString(); }
                catch { lang = "ar"; }
                var user = UserManager.GetUserId(User);
                if (user != null)
                {
                    List<VMShowEvent> showEvents = new();
                    var eve = await Repository.ShowAll(user);
                    if (eve == null) { return null; }
                    foreach (var item in eve)
                    {
                        showEvents.Add(new VMShowEvent
                        {
                            Description = lang == "en" ? item.EnDescription : item.ArDescription,
                            Location = lang == "en" ? item.EnLocation : item.ArLocation,
                            Name = lang == "en" ? item.EnName : item.ArName,
                            Late = item.Late,
                            Long = item.Long,
                            EventDate = item.EventDate,
                            EventTicket = item.EventTicket
                        });
                    }
                    return showEvents;
                }
                return null;
            }
            catch { throw; }
        }
        [HttpGet]
        [Route("GetAllBookingForEvent")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "Employee")]
        public async Task<ActionResult<List<VMEventBooking>?>> GetAllBookingForEvent(Guid id)
        {
            try
            {
                string? user = UserManager.GetUserId(User);
                if(user == null) { return null; }
                return await Repository.GetEventBooking(id, user);
            }
            catch { throw; }
        }
        [HttpPost]
        [Route("Add")]
        [Authorize(AuthenticationSchemes = "Bearer",Roles = "Employee")]
        public async Task<ActionResult<bool>> Add([FromBody] VMEvent vMEvetn)
        {
            try
            {
                if(!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if (user == null) { return false; }
                return await Repository.Add(vMEvetn,user);
            }
            catch { throw; }
        }
        [HttpPut]
        [Route("Update")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "Employee")]
        public async Task<ActionResult<bool>> Update(Guid id,[FromBody] VMEvent vMEvetn)
        {
            try
            {
                if(!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if(user == null) { return false; }
                bool eve = await Repository.Update(id,vMEvetn,user);
                return eve;
            }catch { throw; }
        }
        [HttpDelete]
        [Route("Delete")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = "Employee")]
        public async Task<ActionResult<bool>> Delete(Guid id)
        {
            try
            {
                if (!ModelState.IsValid) { return false; }
                string? user = UserManager.GetUserId(User);
                if(user == null) { return false; }
                return await Repository.Remove(id,user);
            }
            catch { throw; }
        }
    }
}
