from simulation.messages import TAG_PAYLOAD, ApplicationMessage
from simulation.multicast.base import SendingStrategy


class SequentialUnicastStrategy(SendingStrategy):
    def __init__(self, sim, user, group, app, p=1):
        super().__init__(sim, user, group, app)
        self.user.set_split(p)

    def name(self):
        if self.p == 1:
            return "unicast"
        return f"unicast-p{self.p}"

    def on_receive(self, msg):
        #opt assert isinstance(msg, ApplicationMessage)
        self._deliver(msg)

    def send_to_group(self, payload):
        result = []
        for recipient in self.group.users:
            if recipient == self.user:
                continue

            m = ApplicationMessage(
                recipient=recipient,
                tag=TAG_PAYLOAD,
                body=payload,
                group_id=self.group.id,
            )
            self.user.schedule_for_send(m)

        return result

    def tick(self, sim):
        #opt assert sim == self.sim
        # no book keeping necessary with simple unicast
        pass
