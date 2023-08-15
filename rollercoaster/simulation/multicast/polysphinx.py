from simulation.messages import TAG_PAYLOAD, TAG_MULTI, Message, ApplicationMessage, WrappedMessage, WrappedMultiMessage
from simulation.multicast.base import SendingStrategy


class PolysphinxStrategy(SendingStrategy):
    def __init__(self, sim, user, group, app, p, max_level=0):
        """Initialize a PolySphinx multicast strategy.

        p: The multicast level.
        hops_between: Number of hops between any two edge or multiplication
            nodes.
        """
        super().__init__(sim, user, group, app)
        self.p = p
        self.max_level = max_level

    def name(self):
        return "polysphinx-p{}".format(self.p)

    def tick(self, sim):
        pass

    def on_receive(self, msg):
        self._deliver(msg)

    def send_to_group(self, payload):
        messages = [
            ApplicationMessage(
                recipient=group_member,
                tag=TAG_PAYLOAD,
                body=payload,
                group_id=self.group.id,
            )
            for group_member in self.group.users
            if group_member != self.user
        ]
        messages = [
            WrappedMessage(
                m.recipient.provider,
                TAG_MULTI,
                m,
                delay=self.sim.rnd.poisson_delay(self.user.rate_delay),
            )
            for m in messages
        ]

        current_level = 0
        while len(messages) > 1 and (current_level < self.max_level or self.max_level == 0):
            next_level = []
            for i in range(0, len(messages), self.p):
                bunch = []
                for m in messages[i:i+self.p]:
                    for layer in self.sim.network.layers[1:]:
                        random_middleman = self.sim.rnd.choice(layer)
                        m = WrappedMessage(
                            random_middleman,
                            TAG_MULTI,
                            m,
                            delay=self.sim.rnd.poisson_delay(self.user.rate_delay),
                        )
                    bunch.append(m)

                wrapped = WrappedMultiMessage(
                    self.sim.rnd.choice(self.sim.network.layers[0]),
                    TAG_MULTI,
                    bunch,
                    delay=self.sim.rnd.poisson_delay(self.user.rate_delay),
                )
                next_level.append(wrapped)
            messages = next_level
            current_level += 1

        for m in messages:
            self.user.schedule_for_send(m)
